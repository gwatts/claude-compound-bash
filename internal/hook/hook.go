// Package hook implements the PreToolUse hook orchestrator.
// It parses compound bash commands, extracts all executable sub-commands,
// and checks each against the user's allow patterns.
package hook

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gwatts/claude-compound-bash/internal/logfile"
	"github.com/gwatts/claude-compound-bash/internal/matcher"
	"github.com/gwatts/claude-compound-bash/internal/parser"
)

// HookInput is the JSON structure received on stdin from Claude Code.
type HookInput struct {
	ToolName  string    `json:"tool_name"`
	ToolInput ToolInput `json:"tool_input"`
	Cwd       string    `json:"cwd"`
}

// ToolInput holds the tool-specific parameters.
type ToolInput struct {
	Command string `json:"command"`
}

// HookOutput is the JSON structure written to stdout.
type HookOutput struct {
	// HookSpecificOutput is set when we make a permission decision.
	HookSpecificOutput *HookSpecific `json:"hookSpecificOutput,omitempty"`
}

// HookSpecific contains the permission decision.
type HookSpecific struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

// ResultKind classifies the outcome of processing a hook event.
type ResultKind int

const (
	// ResultAsk means one or more commands were not in the allow list.
	// Defers to Claude Code's normal permission prompt.
	ResultAsk ResultKind = iota
	// ResultAllowed means all commands matched allow rules or were inert.
	ResultAllowed
	// ResultParseError means the command could not be parsed.
	ResultParseError
	// ResultDenyRule means a command matched an explicit deny pattern.
	// The tool call is cancelled outright.
	ResultDenyRule
)

// Result represents the outcome of processing a hook event.
type Result struct {
	// Kind classifies the outcome.
	Kind ResultKind
	// Reason describes why the decision was made.
	Reason string
	// BlockedCommand is the first command that didn't match, if any.
	BlockedCommand string
}

// Process evaluates a hook input against the given allow and deny patterns.
// If any sub-command matches a deny pattern, the result is not allowed (defers
// to Claude Code). This matches Claude Code's own "deny always wins" semantics.
func Process(input *HookInput, patterns []matcher.Pattern, askPatterns []matcher.Pattern, denyPatterns []matcher.Pattern, log *logfile.Logger) Result {
	if input.ToolName != "Bash" {
		return Result{Kind: ResultAsk, Reason: "not a Bash tool call"}
	}

	command := input.ToolInput.Command
	if command == "" {
		return Result{Kind: ResultAsk, Reason: "empty command"}
	}

	log.Log("evaluating: %s", truncate(command, 200))

	// Parse the command into individual executable commands.
	commands, err := parser.Parse(command)
	if err != nil {
		log.Log("parse error: %v", err)
		return Result{
			Kind:   ResultParseError,
			Reason: fmt.Sprintf("could not parse command: %v", err),
		}
	}

	if len(commands) == 0 {
		log.Log("ALLOW: no executable commands (pure assignment or empty)")
		return Result{
			Kind:   ResultAllowed,
			Reason: "no executable commands",
		}
	}

	log.Log("parsed %d sub-command(s)", len(commands))

	for _, cmd := range commands {
		result, reason := checkCommand(cmd, patterns, askPatterns, denyPatterns, log)
		switch result {
		case commandAllowed:
			log.Log("  ok [%s]: %s", cmd.String(), reason)
		case commandDenied:
			log.Log("DENY [%s]: %s", cmd.String(), reason)
			return Result{
				Kind:           ResultDenyRule,
				Reason:         reason,
				BlockedCommand: cmd.String(),
			}
		default:
			log.Log("ASK [%s]: %s", cmd.String(), reason)
			return Result{
				Kind:           ResultAsk,
				Reason:         reason,
				BlockedCommand: cmd.String(),
			}
		}
	}

	reason := fmt.Sprintf("all %d sub-command(s) matched", len(commands))
	log.Log("ALLOW: %s", reason)
	return Result{
		Kind:   ResultAllowed,
		Reason: reason,
	}
}

// commandResult represents the outcome of checking a single command.
type commandResult int

const (
	commandAllowed commandResult = iota
	commandAsk                   // not in allow list
	commandDenied                // matched deny rule
)

// checkCommand determines if a single command is allowed.
func checkCommand(cmd parser.Command, patterns []matcher.Pattern, askPatterns []matcher.Pattern, denyPatterns []matcher.Pattern, log *logfile.Logger) (commandResult, string) {
	// Dynamic command names — can't determine what runs.
	if cmd.Dynamic {
		return commandAsk, fmt.Sprintf("dynamic command name in %q", cmd.String())
	}

	name := cmd.Name
	cmdStr := strings.Join(cmd.Args, " ")

	// Evaluation order: deny → ask → allow (first match wins).

	// Deny rules always win.
	if len(denyPatterns) > 0 && matcher.MatchesAny(cmdStr, denyPatterns) {
		return commandDenied, fmt.Sprintf("denied by deny rule: %q", cmdStr)
	}

	// Ask rules override allow rules and safe builtins.
	if len(askPatterns) > 0 && matcher.MatchesAny(cmdStr, askPatterns) {
		return commandAsk, fmt.Sprintf("matched ask rule: %q", cmdStr)
	}

	// Check safety tier for builtins.
	tier := parser.ClassifyBuiltin(name)
	switch tier {
	case parser.TierAlwaysInert:
		return commandAllowed, fmt.Sprintf("%q is always-inert builtin", name)

	case parser.TierInertIfLiteral:
		// Inert builtins (echo, cd, pwd, etc.) are safe regardless of argument
		// literalness. Any commands embedded via $(...) or <(...) are extracted
		// by the AST walker and checked as separate entries.
		return commandAllowed, fmt.Sprintf("%q is inert builtin", name)

	case parser.TierNeverAllow:
		// source, eval, exec, etc. — never auto-allow, must match a pattern.
		log.Log("%q is never-auto-allow builtin, checking patterns", name)
	}

	// Check against allow patterns.
	if matcher.MatchesAny(cmdStr, patterns) {
		return commandAllowed, fmt.Sprintf("matched allow pattern for %q", cmdStr)
	}

	return commandAsk, fmt.Sprintf("not in allow list: %q", cmdStr)
}

// MarshalAllow produces the JSON output for an allow decision.
func MarshalAllow(reason string) ([]byte, error) {
	out := HookOutput{
		HookSpecificOutput: &HookSpecific{
			HookEventName:            "PreToolUse",
			PermissionDecision:       "allow",
			PermissionDecisionReason: reason,
		},
	}
	return json.Marshal(out)
}

// MarshalDeny produces the JSON output that cancels the tool call.
// Used when a command matches an explicit deny pattern.
func MarshalDeny(reason string) ([]byte, error) {
	out := HookOutput{
		HookSpecificOutput: &HookSpecific{
			HookEventName:            "PreToolUse",
			PermissionDecision:       "deny",
			PermissionDecisionReason: reason,
		},
	}
	return json.Marshal(out)
}

// MarshalAsk produces the JSON output that defers to Claude Code's normal
// permission prompt. Used when the hook can't approve a command.
func MarshalAsk(reason string) ([]byte, error) {
	out := HookOutput{
		HookSpecificOutput: &HookSpecific{
			HookEventName:            "PreToolUse",
			PermissionDecision:       "ask",
			PermissionDecisionReason: reason,
		},
	}
	return json.Marshal(out)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

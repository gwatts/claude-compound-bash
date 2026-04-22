// Package hook implements the PreToolUse hook orchestrator.
// It parses compound bash commands, extracts all executable sub-commands,
// and checks each against the user's allow patterns.
package hook

import (
	"encoding/json"
	"fmt"
	"path/filepath"
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

// Process evaluates a hook input against the given allow, ask, and deny patterns.
// Evaluation order matches Claude Code: deny → ask → allow (first match wins).
// additionalDirectories specifies extra directories where output redirects are allowed.
func Process(input *HookInput, allowPatterns []matcher.Pattern, askPatterns []matcher.Pattern, denyPatterns []matcher.Pattern, additionalDirectories []string, log *logfile.Logger) Result {
	if input.ToolName != "Bash" {
		return Result{Kind: ResultAsk, Reason: "not a Bash tool call"}
	}

	command := input.ToolInput.Command
	if command == "" {
		return Result{Kind: ResultAsk, Reason: "empty command"}
	}

	log.Log("evaluating: %s", truncate(command, 200))

	// Parse the command into individual executable commands and redirects.
	parseResult, err := parser.Parse(command)
	if err != nil {
		log.Log("parse error: %v", err)
		return Result{
			Kind:   ResultParseError,
			Reason: fmt.Sprintf("could not parse command: %v", err),
		}
	}

	commands := parseResult.Commands

	if len(commands) == 0 && len(parseResult.Redirects) == 0 {
		log.Log("ALLOW: no executable commands or redirects (pure assignment or empty)")
		return Result{
			Kind:   ResultAllowed,
			Reason: "no executable commands",
		}
	}

	log.Log("parsed %d sub-command(s), %d redirect(s)", len(commands), len(parseResult.Redirects))

	// PHASE 1: Check all commands for DENY patterns first.
	// Deny rules must always win, even if redirects would trigger ask.
	for _, cmd := range commands {
		if cmd.Dynamic {
			continue // Dynamic commands can't match deny patterns by name
		}
		cmdStr := strings.Join(cmd.Args, " ")
		if len(denyPatterns) > 0 && matcher.MatchesAny(cmdStr, denyPatterns) {
			reason := fmt.Sprintf("denied by deny rule: %q", cmdStr)
			log.Log("DENY [%s]: %s", cmd.String(), reason)
			return Result{
				Kind:           ResultDenyRule,
				Reason:         reason,
				BlockedCommand: cmd.String(),
			}
		}
	}

	// PHASE 2: Check redirects (output redirects only, per design decision)
	// Expand additional output directories (handles /tmp -> /private/tmp on macOS)
	expandedDirs, err := parser.ExpandAdditionalDirs(additionalDirectories)
	if err != nil {
		log.Log("config error: %v", err)
		return Result{
			Kind:   ResultAsk,
			Reason: fmt.Sprintf("configuration error: %v", err),
		}
	}

	// If command contains cwd-changers or link creators, relative paths can't be trusted
	hasPathMutator := parseResult.HasCwdChanger || parseResult.HasLinkCreator

	for _, redir := range parseResult.Redirects {
		result := checkRedirect(redir, input.Cwd, expandedDirs, hasPathMutator, log)
		if result.Kind != ResultAllowed {
			return result
		}
	}

	// PHASE 3: Check commands for ask/allow (deny already handled above)
	for _, cmd := range commands {
		result, reason := checkCommand(cmd, allowPatterns, askPatterns, denyPatterns, log)
		switch result {
		case commandAllowed:
			log.Log("  ok [%s]: %s", cmd.String(), reason)
		case commandDenied:
			// Already checked in phase 1, but checkCommand may still return this
			// for edge cases. Honor it.
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
func checkCommand(cmd parser.Command, allowPatterns []matcher.Pattern, askPatterns []matcher.Pattern, denyPatterns []matcher.Pattern, log *logfile.Logger) (commandResult, string) {
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

	case parser.TierSafeBuiltin:
		return commandAllowed, fmt.Sprintf("%q is safe builtin", name)

	case parser.TierNeverAllow:
		// source, eval, exec, etc. — never auto-allow, must match a pattern.
		log.Log("%q is never-auto-allow builtin, checking patterns", name)
	}

	// Check against allow patterns.
	if matcher.MatchesAny(cmdStr, allowPatterns) {
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

// checkRedirect evaluates a single redirect for safety.
// Returns ResultAllowed if the redirect can be auto-approved,
// or ResultAsk if user confirmation is needed.
// hasPathMutator indicates if the command contains cd/pushd/popd/ln, making relative paths unsafe.
func checkRedirect(redir parser.RedirectInfo, cwd string, additionalDirs []string, hasPathMutator bool, log *logfile.Logger) Result {
	// Skip input redirects (only check outputs per design decision)
	if !redir.IsOutput() {
		return Result{Kind: ResultAllowed}
	}

	// FD-to-FD duplications (2>&1) are always safe
	if redir.IsFDDup() {
		log.Log("  redirect ok [%s]: fd-to-fd duplication", redir.Raw)
		return Result{Kind: ResultAllowed}
	}

	// Heredocs are always safe (no file path)
	if redir.IsHeredoc {
		log.Log("  redirect ok [%s]: heredoc", redir.Raw)
		return Result{Kind: ResultAllowed}
	}

	// Dynamic targets (variables, globs, tilde) require ask
	if !redir.TargetLiteral {
		log.Log("ASK [%s]: dynamic redirect target", redir.Raw)
		return Result{
			Kind:           ResultAsk,
			Reason:         fmt.Sprintf("redirect target is dynamic: %q", redir.Raw),
			BlockedCommand: redir.Raw,
		}
	}

	// Check for safe device files
	if parser.IsSafeDevice(redir.Target) {
		log.Log("  redirect ok [%s]: safe device", redir.Raw)
		return Result{Kind: ResultAllowed}
	}

	// If command contains path-mutating commands (cd, pushd, popd, ln), relative paths
	// cannot be validated reliably - we don't know the effective target at execution time.
	if hasPathMutator && !filepath.IsAbs(redir.Target) {
		log.Log("ASK [%s]: relative path with path-mutating command", redir.Raw)
		return Result{
			Kind:           ResultAsk,
			Reason:         fmt.Sprintf("relative redirect with path-mutating command (cd/ln/etc): %q", redir.Raw),
			BlockedCommand: redir.Raw,
		}
	}

	// Resolve the path (handling symlinks)
	resolved, err := parser.ResolvePath(redir.Target, cwd)
	if err != nil {
		log.Log("ASK [%s]: cannot resolve path: %v", redir.Raw, err)
		return Result{
			Kind:           ResultAsk,
			Reason:         fmt.Sprintf("cannot resolve redirect path: %q", redir.Target),
			BlockedCommand: redir.Raw,
		}
	}

	// Check for protected paths inside cwd (.git, .claude)
	if parser.IsProtectedPath(resolved, cwd) {
		log.Log("ASK [%s]: protected directory (resolved to %s)", redir.Raw, resolved)
		return Result{
			Kind:           ResultAsk,
			Reason:         fmt.Sprintf("redirect to protected directory: %q (resolved to %s)", redir.Target, resolved),
			BlockedCommand: redir.Raw,
		}
	}

	// Check if path is inside cwd or additional allowed directories
	if parser.IsInsideAllowedDir(resolved, cwd, additionalDirs) {
		log.Log("  redirect ok [%s]: within allowed directory", redir.Raw)
		return Result{Kind: ResultAllowed}
	}

	// Path is outside allowed directories - ask
	log.Log("ASK [%s]: output outside allowed directories (resolved to %s)", redir.Raw, resolved)
	return Result{
		Kind:           ResultAsk,
		Reason:         fmt.Sprintf("redirect outside allowed directories: %q (resolved to %s)", redir.Target, resolved),
		BlockedCommand: redir.Raw,
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

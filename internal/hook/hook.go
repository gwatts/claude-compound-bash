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
	// ResultAsk means the hook actively wants Claude Code to prompt: a command
	// matched an explicit ask rule, or a redirect failed a safety check that the
	// native permission system doesn't perform. The hook emits an "ask" decision.
	ResultAsk ResultKind = iota
	// ResultAllowed means all commands matched allow rules or were inert.
	ResultAllowed
	// ResultParseError means the command could not be parsed.
	ResultParseError
	// ResultDenyRule means a command matched an explicit deny pattern.
	// The tool call is cancelled outright.
	ResultDenyRule
	// ResultDefer means the hook has no opinion — it can't affirmatively allow
	// the command (nothing matched the allow list, or the command couldn't be
	// classified), but it also has no reason to force a prompt. The hook emits no
	// decision so Claude Code's own permission flow (read-only sets, wrapper
	// stripping, its own rules) decides. This keeps the hook strictly additive:
	// it only ever upgrades a call to allow/deny, never adds a prompt native
	// wouldn't have shown on its own.
	ResultDefer
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
		return Result{Kind: ResultDefer, Reason: "not a Bash tool call"}
	}

	command := input.ToolInput.Command
	if command == "" {
		return Result{Kind: ResultDefer, Reason: "empty command"}
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
	// Deny rules must always win, even if redirects would trigger ask. This
	// looks through command wrappers too, so a denied payload (e.g. `xargs rm`
	// with rm denied) is cancelled regardless of any later redirect/ask.
	for _, cmd := range commands {
		if cmd.Dynamic {
			continue // Dynamic outer command can't be unwrapped or matched by name
		}
		if denied, ok := denyMatchDeep(cmd, denyPatterns, false); ok {
			reason := fmt.Sprintf("denied by deny rule: %q", denied)
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

	// PHASE 3: Check commands for ask/allow (deny already handled above).
	//
	// Aggregate over every sub-command rather than returning on the first
	// non-allowed one, with precedence deny > ask > defer > allow. This matters
	// because a top-level unmatched command must not short-circuit a *nested*
	// unmatched command (inside a substitution/subshell/loop) into a defer: the
	// nested command needs a forced ask, since native — which splits only on
	// shell operators — may approve the enclosing read-only command without ever
	// seeing it.
	worst := ResultAllowed
	var worstReason, worstBlocked string
	for _, cmd := range commands {
		result, reason := checkCommand(cmd, allowPatterns, askPatterns, denyPatterns, log)
		switch result {
		case commandAllowed:
			log.Log("  ok [%s]: %s", cmd.String(), reason)
		case commandDenied:
			// Already checked in phase 1, but checkCommand may still return this
			// for edge cases. Deny wins outright.
			log.Log("DENY [%s]: %s", cmd.String(), reason)
			return Result{Kind: ResultDenyRule, Reason: reason, BlockedCommand: cmd.String()}
		case commandAsk:
			// An explicit ask rule matched. Force the prompt — native might miss
			// this (e.g. an ask rule on a wrapper it strips), so we assert it.
			log.Log("ASK [%s]: %s", cmd.String(), reason)
			if worst != ResultAsk {
				worst, worstReason, worstBlocked = ResultAsk, reason, cmd.String()
			}
		default: // commandDefer
			if cmd.Nested {
				// Native's operator splitting can't see this command; force a
				// prompt rather than defer to it.
				log.Log("ASK [%s]: %s (nested; native would not see it)", cmd.String(), reason)
				if worst != ResultAsk {
					worst, worstReason, worstBlocked = ResultAsk, reason, cmd.String()
				}
			} else {
				// Top-level unmatched: native splits the compound the same way we
				// do, so let it decide. Defer only if nothing stronger was seen.
				log.Log("DEFER [%s]: %s", cmd.String(), reason)
				if worst == ResultAllowed {
					worst, worstReason, worstBlocked = ResultDefer, reason, cmd.String()
				}
			}
		}
	}

	if worst == ResultAllowed {
		reason := fmt.Sprintf("all %d sub-command(s) matched", len(commands))
		log.Log("ALLOW: %s", reason)
		return Result{Kind: ResultAllowed, Reason: reason}
	}
	return Result{Kind: worst, Reason: worstReason, BlockedCommand: worstBlocked}
}

// commandResult represents the outcome of checking a single command.
type commandResult int

const (
	commandAllowed commandResult = iota
	commandDefer                 // can't affirmatively allow — defer to native
	commandAsk                   // matched an explicit ask rule — force a prompt
	commandDenied                // matched deny rule
)

// maxWrapperDepth bounds how deep wrapper unwrapping recurses (e.g. xargs
// invoking find -exec). Real commands never nest this far; the bound just
// guarantees termination and fails closed on absurd input.
const maxWrapperDepth = 3

// checkCommand determines if a single command is allowed.
func checkCommand(cmd parser.Command, allowPatterns []matcher.Pattern, askPatterns []matcher.Pattern, denyPatterns []matcher.Pattern, log *logfile.Logger) (commandResult, string) {
	return checkCommandDepth(cmd, allowPatterns, askPatterns, denyPatterns, log, 0, false)
}

// matchesAppendAware reports whether any pattern matches the command, accounting
// for xargs-appended runtime args. When appendsArgs is true the command actually
// runs as cmdStr plus at least one stdin-derived trailing token, so a pattern
// that matches only the extended form (a trailing wildcard) still applies. Deny
// and ask use this so they see the same extended command the allow path does —
// otherwise `xargs rm /tmp/safe` could be approved via `Bash(rm /tmp/safe*)`
// while its runtime form `rm /tmp/safe <stdin>` slips a `Bash(rm /tmp/safe *)`
// deny.
func matchesAppendAware(cmdStr string, patterns []matcher.Pattern, appendsArgs bool) bool {
	if matcher.MatchesAny(cmdStr, patterns) {
		return true
	}
	return appendsArgs && matcher.MatchesAnyAllowingTrailingArgs(cmdStr, patterns)
}

// denyMatchDeep returns the first command — cmd itself or any command it wraps
// (xargs/find -exec, recursively) — that matches a deny pattern. Because deny
// must win over every other decision, Process consults this in PHASE 1, before
// the redirect and ask/allow phases.
//
// Unlike the approval path (checkCommandDepth), this traversal is deliberately
// NOT bounded by maxWrapperDepth. Deny is safety-critical and must never fail
// open: bounding the search would let a denied payload buried under enough
// wrapper layers (e.g. `xargs xargs xargs xargs rm`) escape the deny and be
// downgraded to an ask. Termination is still guaranteed because every unwrapped
// payload (args[i:] for xargs, the -exec slice for find) is a strict sub-slice
// of its parent's args, so the argument count shrinks by at least one per level.
func denyMatchDeep(cmd parser.Command, denyPatterns []matcher.Pattern, inheritedAppend bool) (string, bool) {
	if len(denyPatterns) == 0 {
		return "", false
	}
	appendsArgs := cmd.AppendsArgs || inheritedAppend
	if !cmd.Dynamic {
		cmdStr := strings.Join(cmd.Args, " ")
		if matchesAppendAware(cmdStr, denyPatterns, appendsArgs) {
			return cmdStr, true
		}
	}
	if inners, isWrapper := parser.WrapperInner(cmd); isWrapper {
		for _, inner := range inners {
			if denied, ok := denyMatchDeep(inner, denyPatterns, appendsArgs); ok {
				return denied, true
			}
		}
	}
	return "", false
}

// checkCommandDepth classifies one command. inheritedAppend is true when an
// enclosing wrapper appends arguments at runtime (an xargs payload), which flows
// down so the eventual leaf command is only auto-approved by a rule that
// tolerates those extra arguments.
func checkCommandDepth(cmd parser.Command, allowPatterns []matcher.Pattern, askPatterns []matcher.Pattern, denyPatterns []matcher.Pattern, log *logfile.Logger, depth int, inheritedAppend bool) (commandResult, string) {
	// Dynamic command names — can't determine what runs, so we can't allow it.
	// Defer rather than force a prompt: native evaluates it too.
	if cmd.Dynamic {
		return commandDefer, fmt.Sprintf("dynamic command name in %q", cmd.String())
	}

	name := cmd.Name
	cmdStr := strings.Join(cmd.Args, " ")
	// This command receives appended runtime args if it's an xargs payload or if
	// an enclosing wrapper appends to it.
	appendsArgs := cmd.AppendsArgs || inheritedAppend

	// Evaluation order: deny → ask → allow (first match wins), with deny always
	// winning — including a deny rule that matches the payload of a wrapper.

	// Deny on this command's own name/args (accounting for appended runtime args).
	if len(denyPatterns) > 0 && matchesAppendAware(cmdStr, denyPatterns, appendsArgs) {
		return commandDenied, fmt.Sprintf("denied by deny rule: %q", cmdStr)
	}

	// Command wrappers (xargs, find -exec) reveal nothing by their own name —
	// classify the command they forward to instead, using the same rules. This
	// keeps `xargs grep`/`find -exec grep` as quiet as a plain grep while still
	// deferring `xargs rm`/`find -exec rm`. The payload is evaluated before any
	// ask rule on the wrapper itself is honored, so a denied payload still wins
	// and is never downgraded. A wrapper whose payload can't be read, or that
	// nests past maxWrapperDepth, defers to native rather than auto-approving.
	if inners, isWrapper := parser.WrapperInner(cmd); isWrapper {
		if depth >= maxWrapperDepth {
			return commandDefer, fmt.Sprintf("%q: wrapper nesting too deep", name)
		}
		// A find that receives runtime-appended args (an xargs payload) is unsafe
		// to approve from its -exec payload alone: xargs appends stdin tokens to
		// the find *expression*, so a mutating action (-delete, another -exec) can
		// be added at run time and never appears in the args we see. Unlike a plain
		// command or process wrapper — whose appended tokens are just arguments to
		// the leaf command — find interprets them as actions. Force a prompt.
		if name == "find" && appendsArgs {
			return commandAsk, fmt.Sprintf("%q receives appended args that could add find actions", name)
		}
		if len(inners) == 0 {
			// A find whose payload we can't read (e.g. `find . -ok CMD`) is a
			// hazard native may approve under a broad `find *` rule — force a
			// prompt. For other wrappers (bare xargs, etc.) native evaluates an
			// equivalent command, so defer.
			if name == "find" {
				return commandAsk, fmt.Sprintf("%q: could not determine wrapped command", name)
			}
			return commandDefer, fmt.Sprintf("%q: could not determine wrapped command", name)
		}
		// Aggregate the payload outcomes by severity: denied wins outright; an
		// explicit ask beats a defer; a defer beats an allow. (Deny was already
		// ruled out for this command's own name/args above, and denyMatchDeep in
		// PHASE 1 has looked through the whole wrapper nest.)
		outerAsk := len(askPatterns) > 0 && matchesAppendAware(cmdStr, askPatterns, appendsArgs)
		result, reason := commandAllowed, fmt.Sprintf("%q wraps approved command(s)", name)
		for _, inner := range inners {
			res, r := checkCommandDepth(inner, allowPatterns, askPatterns, denyPatterns, log, depth+1, appendsArgs)
			switch res {
			case commandDenied:
				return commandDenied, fmt.Sprintf("%q wraps denied command: %s", name, r)
			case commandAsk:
				if result != commandAsk {
					result, reason = commandAsk, fmt.Sprintf("%q wraps command needing confirmation: %s", name, r)
				}
			case commandDefer:
				if result == commandAllowed {
					result, reason = commandDefer, fmt.Sprintf("%q wraps unapproved command: %s", name, r)
				}
			}
		}
		// An explicit ask rule — matched by a payload or by the wrapper itself —
		// forces a prompt, outranking the softer defer outcomes below (deny was
		// already ruled out above).
		if result == commandAsk {
			return commandAsk, reason
		}
		if outerAsk {
			return commandAsk, fmt.Sprintf("matched ask rule: %q", cmdStr)
		}
		// We only validate the -exec/-execdir payload of a find. If the same
		// expression carries another side-effecting action (-delete, -fprintf,
		// -ok, ...), a safe payload must not auto-approve it. This is a definite
		// hazard the hook detected: native's `find *` handling gates -delete/-exec
		// but its treatment of -fprintf/-fls/-ok is unverified, so force a prompt
		// rather than defer.
		if parser.FindHasMutatingNonExecAction(cmd) {
			return commandAsk, fmt.Sprintf("%q has a side-effecting action beyond -exec", name)
		}
		return result, reason
	}

	// Ask rules force a prompt, overriding allow rules and safe builtins
	// (accounting for appended runtime args, as deny above).
	if len(askPatterns) > 0 && matchesAppendAware(cmdStr, askPatterns, appendsArgs) {
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

	// Check against allow patterns. When runtime args will be appended (an xargs
	// payload), require a rule that tolerates them, so an exact rule can't approve
	// a command xargs will silently extend with stdin-derived tokens.
	if appendsArgs {
		if matcher.MatchesAnyAllowingTrailingArgs(cmdStr, allowPatterns) {
			return commandAllowed, fmt.Sprintf("matched allow pattern (with appended args) for %q", cmdStr)
		}
		if matcher.MatchesAny(cmdStr, allowPatterns) {
			// The static form matches a rule, but that rule doesn't cover the
			// appended args. Deferring would be unsafe: native strips (bare) xargs
			// and would approve on this same rule without seeing the appended
			// tokens. Force a prompt instead.
			return commandAsk, fmt.Sprintf("xargs payload matches only a rule that doesn't cover its appended args: %q", cmdStr)
		}
		return commandDefer, fmt.Sprintf("not in allow list for appended-args command: %q", cmdStr)
	}
	if matcher.MatchesAny(cmdStr, allowPatterns) {
		return commandAllowed, fmt.Sprintf("matched allow pattern for %q", cmdStr)
	}

	return commandDefer, fmt.Sprintf("not in allow list: %q", cmdStr)
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

// claude-compound-bash is a Claude Code PreToolUse hook that auto-approves
// compound bash commands when every sub-command individually matches the
// user's allow rules.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/gwatts/claude-compound-bash/internal/hook"
	"github.com/gwatts/claude-compound-bash/internal/logfile"
	"github.com/gwatts/claude-compound-bash/internal/matcher"
	"github.com/gwatts/claude-compound-bash/internal/settings"
)

// version is set by goreleaser via ldflags.
var version = "dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--version", "-v":
			fmt.Println("claude-compound-bash " + version)
			return
		case "--help", "-h":
			fmt.Println(`claude-compound-bash — auto-approve compound bash commands for Claude Code

Usage: Intended to run as a Claude Code PreToolUse hook. Reads hook
input JSON from stdin and writes a permission decision to stdout.

Flags:
  --version, -v    Print version and exit
  --help, -h       Print this help and exit

See https://github.com/gwatts/claude-compound-bash for details.`)
			return
		}
	}

	// If stdin is a terminal, the user ran this interactively rather than
	// as a hook (which always pipes JSON on stdin). Show help and exit.
	if fi, err := os.Stdin.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		fmt.Fprintln(os.Stderr, "claude-compound-bash "+version)
		fmt.Fprintln(os.Stderr, "This is a Claude Code PreToolUse hook. It reads hook input JSON from stdin.")
		fmt.Fprintln(os.Stderr, "Run with --help for more information.")
		os.Exit(0)
	}

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	log, err := logfile.Open("")
	if err != nil {
		// If we can't open the log, proceed without logging.
		log = logfile.NopLogger()
	}
	defer func() { _ = log.Close() }()

	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}

	var input hook.HookInput
	if err := json.Unmarshal(data, &input); err != nil {
		// Can't parse hook input — defer to manual approval.
		log.Log("invalid hook input: %v", err)
		output, mErr := hook.MarshalParseError()
		if mErr != nil {
			return fmt.Errorf("marshal parse-error output: %w", mErr)
		}
		_, wErr := os.Stdout.Write(output)
		return wErr
	}

	// Only handle Bash tool calls.
	if input.ToolName != "Bash" {
		return nil
	}

	// Load allow/deny patterns from user and project settings.
	perms, err := settings.LoadPermissions(input.Cwd)
	if err != nil {
		log.Log("failed to load settings: %v", err)
		perms = &settings.ResolvedPermissions{}
	}

	allowPatterns := matcher.ParsePatterns(perms.Allow)
	denyPatterns := matcher.ParsePatterns(perms.Deny)
	if len(allowPatterns) == 0 {
		// No allow patterns configured — nothing to do.
		return nil
	}

	result := hook.Process(&input, allowPatterns, denyPatterns, log)

	var output []byte
	switch result.Kind {
	case hook.ResultAllowed:
		output, err = hook.MarshalAllow(result.Reason)
	case hook.ResultParseError:
		output, err = hook.MarshalParseError()
	default:
		output, err = hook.MarshalDeny(result.BlockedCommand, result.Reason)
	}
	if err != nil {
		return fmt.Errorf("marshal output: %w", err)
	}

	_, err = os.Stdout.Write(output)
	return err
}

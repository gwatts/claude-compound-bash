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

func main() {
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

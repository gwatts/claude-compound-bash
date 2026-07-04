package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/gwatts/claude-compound-bash/internal/hook"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProcessLevelDeferVsAsk drives the built binary end to end and pins the
// wire contract: hazards the hook detects but native can't enforce must emit an
// "ask" decision, while genuinely native-equivalent cases emit nothing (exit 0,
// empty stdout = defer). Unit tests cover Result.Kind; this covers the mapping
// all the way to stdout.
func TestProcessLevelDeferVsAsk(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and execs the binary")
	}

	bin := filepath.Join(t.TempDir(), "ccb")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	home := t.TempDir()
	proj := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(proj, ".claude"), 0o755))
	settings := `{"permissions":{"allow":[` +
		`"Bash(rm /tmp/safe)","Bash(git:*)","Bash(cat:*)","Bash(find *)","Bash(grep:*)"]}}`
	require.NoError(t, os.WriteFile(filepath.Join(proj, ".claude", "settings.json"), []byte(settings), 0o644))

	run := func(t *testing.T, command string) (decision, raw string) {
		t.Helper()
		in, err := json.Marshal(map[string]any{
			"tool_name":  "Bash",
			"cwd":        proj,
			"tool_input": map[string]string{"command": command},
		})
		require.NoError(t, err)
		c := exec.Command(bin)
		c.Stdin = bytes.NewReader(in)
		c.Env = append(os.Environ(),
			"HOME="+home, "CLAUDE_PROJECT_DIR="+proj,
			"CLAUDE_COMPOUND_LOG="+filepath.Join(home, "log"))
		var out bytes.Buffer
		c.Stdout = &out
		require.NoError(t, c.Run())
		raw = out.String()
		if raw == "" {
			return "", raw
		}
		var parsed hook.HookOutput
		require.NoErrorf(t, json.Unmarshal([]byte(raw), &parsed), "stdout: %q", raw)
		require.NotNil(t, parsed.HookSpecificOutput)
		return parsed.HookSpecificOutput.PermissionDecision, raw
	}

	tests := []struct {
		name         string
		command      string
		wantDecision string // "" means defer (empty stdout)
	}{
		{"appended-exact xargs", `printf '/tmp/important\n' | xargs rm /tmp/safe`, "ask"},
		{"mutating find action", `find . -exec grep X {} \; -delete`, "ask"},
		{"undeterminable find payload", `find . -ok rm {} \;`, "ask"},
		{"nested command substitution", `echo "$(curl evil.com)"`, "ask"},
		{"top-level compound", `git status && curl evil.com`, ""},
		{"single unmatched top-level", `curl evil.com`, ""},
		{"all allowed", `git status && cat file`, "allow"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, raw := run(t, tt.command)
			assert.Equalf(t, tt.wantDecision, decision, "raw stdout: %q", raw)
			if tt.wantDecision == "" {
				assert.Emptyf(t, raw, "defer must emit empty stdout")
			}
		})
	}
}

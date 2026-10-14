package settings

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadPermissionsWithProjectDir(t *testing.T) {
	// Create a fake project dir with .claude/settings.json.
	projectDir := t.TempDir()
	claudeDir := filepath.Join(projectDir, ".claude")
	require.NoError(t, os.MkdirAll(claudeDir, 0700))

	content := `{
  "permissions": {
    "allow": ["Bash(npm:*)"],
    "deny": ["Bash(npm publish:*)"]
  }
}`
	require.NoError(t, os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte(content), 0600))
	t.Setenv("CLAUDE_PROJECT_DIR", projectDir)

	perms, err := LoadPermissions()
	require.NoError(t, err)

	// Should include project allow patterns (plus any from user home, which may or may not exist).
	assert.Contains(t, perms.Allow, "Bash(npm:*)")
	assert.Contains(t, perms.Deny, "Bash(npm publish:*)")
}

func TestLoadPermissionsNoProjectDir(t *testing.T) {
	// With no project dir set, should still load user settings without error.
	t.Setenv("CLAUDE_PROJECT_DIR", "")

	perms, err := LoadPermissions()
	require.NoError(t, err)
	assert.NotNil(t, perms)
}

func TestLoadPermissionsMergesMultipleFiles(t *testing.T) {
	projectDir := t.TempDir()
	claudeDir := filepath.Join(projectDir, ".claude")
	require.NoError(t, os.MkdirAll(claudeDir, 0700))

	settings := `{"permissions": {"allow": ["Bash(git:*)"]}}`
	settingsLocal := `{"permissions": {"allow": ["Bash(go:*)"], "deny": ["Bash(rm:*)"]}}`
	require.NoError(t, os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte(settings), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(claudeDir, "settings.local.json"), []byte(settingsLocal), 0600))
	t.Setenv("CLAUDE_PROJECT_DIR", projectDir)

	perms, err := LoadPermissions()
	require.NoError(t, err)

	assert.Contains(t, perms.Allow, "Bash(git:*)")
	assert.Contains(t, perms.Allow, "Bash(go:*)")
	assert.Contains(t, perms.Deny, "Bash(rm:*)")
}

func TestLoadPermissionsNoPermissionsKey(t *testing.T) {
	projectDir := t.TempDir()
	claudeDir := filepath.Join(projectDir, ".claude")
	require.NoError(t, os.MkdirAll(claudeDir, 0700))

	require.NoError(t, os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte(`{}`), 0600))
	t.Setenv("CLAUDE_PROJECT_DIR", projectDir)

	perms, err := LoadPermissions()
	require.NoError(t, err)
	assert.NotNil(t, perms)
}

func TestLoadPermissionsHonorsCLAUDE_CONFIG_DIR(t *testing.T) {
	// When CLAUDE_CONFIG_DIR is set, the loader should read user settings from
	// there rather than ~/.claude. This mirrors how Claude Code itself resolves
	// the config dir for profile switching (e.g. ~/.claude-work).
	configDir := t.TempDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(configDir, "settings.json"),
		[]byte(`{"permissions": {"allow": ["Bash(profile-only-marker:*)"]}}`),
		0600,
	))
	t.Setenv("CLAUDE_CONFIG_DIR", configDir)
	t.Setenv("CLAUDE_PROJECT_DIR", "")

	perms, err := LoadPermissions()
	require.NoError(t, err)
	assert.Contains(t, perms.Allow, "Bash(profile-only-marker:*)")
}

func TestLoadPermissionsFallsBackToDefaultHome(t *testing.T) {
	// With CLAUDE_CONFIG_DIR unset, the loader must fall back to ~/.claude
	// so users on the default profile see no behavior change.
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	t.Setenv("CLAUDE_PROJECT_DIR", "")

	// Override HOME so the test doesn't depend on the developer's real ~/.claude.
	fakeHome := t.TempDir()
	claudeDir := filepath.Join(fakeHome, ".claude")
	require.NoError(t, os.MkdirAll(claudeDir, 0700))
	require.NoError(t, os.WriteFile(
		filepath.Join(claudeDir, "settings.json"),
		[]byte(`{"permissions": {"allow": ["Bash(fallback-marker:*)"]}}`),
		0600,
	))
	t.Setenv("HOME", fakeHome)

	perms, err := LoadPermissions()
	require.NoError(t, err)
	assert.Contains(t, perms.Allow, "Bash(fallback-marker:*)")
}

func TestLoadPermissionsInvalidJSON(t *testing.T) {
	projectDir := t.TempDir()
	claudeDir := filepath.Join(projectDir, ".claude")
	require.NoError(t, os.MkdirAll(claudeDir, 0700))

	require.NoError(t, os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte(`{invalid`), 0600))
	t.Setenv("CLAUDE_PROJECT_DIR", projectDir)

	// Should not error — invalid files are skipped.
	perms, err := LoadPermissions()
	require.NoError(t, err)
	assert.NotNil(t, perms)
}

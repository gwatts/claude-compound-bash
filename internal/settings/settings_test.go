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

	perms, err := LoadPermissions(projectDir)
	require.NoError(t, err)

	// Should include project allow patterns (plus any from user home, which may or may not exist).
	assert.Contains(t, perms.Allow, "Bash(npm:*)")
	assert.Contains(t, perms.Deny, "Bash(npm publish:*)")
}

func TestLoadPermissionsEmptyCwd(t *testing.T) {
	// With empty cwd, should still load user settings without error.
	perms, err := LoadPermissions("")
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

	perms, err := LoadPermissions(projectDir)
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

	perms, err := LoadPermissions(projectDir)
	require.NoError(t, err)
	assert.NotNil(t, perms)
}

func TestLoadPermissionsInvalidJSON(t *testing.T) {
	projectDir := t.TempDir()
	claudeDir := filepath.Join(projectDir, ".claude")
	require.NoError(t, os.MkdirAll(claudeDir, 0700))

	require.NoError(t, os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte(`{invalid`), 0600))

	// Should not error — invalid files are skipped.
	perms, err := LoadPermissions(projectDir)
	require.NoError(t, err)
	assert.NotNil(t, perms)
}

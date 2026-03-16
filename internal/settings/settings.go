// Package settings reads allow/deny patterns from Claude Code settings files.
package settings

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// settings represents the relevant portion of a Claude Code settings file.
type settings struct {
	Permissions *permissions `json:"permissions"`
}

// permissions holds the allow/deny lists.
type permissions struct {
	Allow []string `json:"allow"`
	Deny  []string `json:"deny"`
}

// ResolvedPermissions holds merged allow/deny patterns ready for use by the hook.
type ResolvedPermissions struct {
	Allow []string
	Deny  []string
}

// LoadPermissions reads allow and deny patterns from the user's global Claude
// Code settings and (optionally) from project-level settings. It reads from:
//   - ~/.claude/settings.json
//   - ~/.claude/settings.local.json
//   - <cwd>/.claude/settings.json      (if cwd is non-empty)
//   - <cwd>/.claude/settings.local.json (if cwd is non-empty)
//
// This matches Claude Code's own behavior: project-level settings are
// auto-trusted. Deny rules from any scope block approval.
func LoadPermissions(cwd string) (*ResolvedPermissions, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	claudeDir := filepath.Join(home, ".claude")
	files := []string{
		filepath.Join(claudeDir, "settings.json"),
		filepath.Join(claudeDir, "settings.local.json"),
	}

	if cwd != "" {
		files = append(files,
			filepath.Join(cwd, ".claude", "settings.json"),
			filepath.Join(cwd, ".claude", "settings.local.json"),
		)
	}

	result := &ResolvedPermissions{}
	for _, path := range files {
		perms, err := loadPermsFromFile(path)
		if err != nil {
			continue
		}
		result.Allow = append(result.Allow, perms.Allow...)
		result.Deny = append(result.Deny, perms.Deny...)
	}

	return result, nil
}

func loadPermsFromFile(path string) (*permissions, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var s settings
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}

	if s.Permissions == nil {
		return &permissions{}, nil
	}

	return s.Permissions, nil
}

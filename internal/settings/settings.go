// Package settings reads allow/ask/deny patterns from Claude Code settings files.
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

// permissions holds the allow/ask/deny lists.
type permissions struct {
	Allow []string `json:"allow"`
	Ask   []string `json:"ask"`
	Deny  []string `json:"deny"`
}

// ResolvedPermissions holds merged allow/ask/deny patterns ready for use by the hook.
type ResolvedPermissions struct {
	Allow   []string
	Ask     []string
	Deny    []string
	Sources []string // settings files that contributed patterns
}

// LoadPermissions reads allow and deny patterns from the user's global Claude
// Code settings and (optionally) from project-level settings. It reads from:
//   - ~/.claude/settings.json
//   - ~/.claude/settings.local.json
//   - <projectDir>/.claude/settings.json      (if set)
//   - <projectDir>/.claude/settings.local.json (if set)
//
// projectDir is read from the CLAUDE_PROJECT_DIR environment variable.
// Project-level settings override user-level settings.
// Deny rules from any scope block approval.
func LoadPermissions() (*ResolvedPermissions, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	claudeDir := filepath.Join(home, ".claude")
	files := []string{
		filepath.Join(claudeDir, "settings.json"),
		filepath.Join(claudeDir, "settings.local.json"),
	}

	projectDir := os.Getenv("CLAUDE_PROJECT_DIR")
	if projectDir != "" {
		files = append(files,
			filepath.Join(projectDir, ".claude", "settings.json"),
			filepath.Join(projectDir, ".claude", "settings.local.json"),
		)
	}

	result := &ResolvedPermissions{}
	for _, path := range files {
		perms, err := loadPermsFromFile(path)
		if err != nil {
			continue
		}
		if len(perms.Allow) > 0 || len(perms.Ask) > 0 || len(perms.Deny) > 0 {
			result.Allow = append(result.Allow, perms.Allow...)
			result.Ask = append(result.Ask, perms.Ask...)
			result.Deny = append(result.Deny, perms.Deny...)
			result.Sources = append(result.Sources, path)
		}
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

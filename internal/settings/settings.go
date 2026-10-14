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
	Allow                 []string `json:"allow"`
	Ask                   []string `json:"ask"`
	Deny                  []string `json:"deny"`
	AdditionalDirectories []string `json:"additionalDirectories,omitempty"`
}

// ResolvedPermissions holds merged allow/ask/deny patterns ready for use by the hook.
type ResolvedPermissions struct {
	Allow                 []string
	Ask                   []string
	Deny                  []string
	AdditionalDirectories []string // directories allowed for output redirects (shared with Claude Code's workspace setting)
	Sources               []string // settings files that contributed patterns
}

// LoadPermissions reads allow and deny patterns from the user's global Claude
// Code settings and (optionally) from project-level settings. It reads from:
//   - $CLAUDE_CONFIG_DIR/settings.json         (falls back to ~/.claude/settings.json if unset)
//   - $CLAUDE_CONFIG_DIR/settings.local.json   (falls back to ~/.claude/settings.local.json)
//   - <projectDir>/.claude/settings.json       (if CLAUDE_PROJECT_DIR is set)
//   - <projectDir>/.claude/settings.local.json (if CLAUDE_PROJECT_DIR is set)
//
// The user-scope directory is CLAUDE_CONFIG_DIR when set, otherwise ~/.claude.
// This matches how Claude Code itself resolves the config directory, so alternate
// profiles (e.g. CLAUDE_CONFIG_DIR=~/.claude-work) resolve to the same settings
// files the user's Claude session is reading.
//
// projectDir is read from the CLAUDE_PROJECT_DIR environment variable.
// Project-level settings override user-level settings.
// Deny rules from any scope block approval.
func LoadPermissions() (*ResolvedPermissions, error) {
	claudeDir := os.Getenv("CLAUDE_CONFIG_DIR")
	if claudeDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		claudeDir = filepath.Join(home, ".claude")
	}

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
		if len(perms.Allow) > 0 || len(perms.Ask) > 0 || len(perms.Deny) > 0 || len(perms.AdditionalDirectories) > 0 {
			result.Allow = append(result.Allow, perms.Allow...)
			result.Ask = append(result.Ask, perms.Ask...)
			result.Deny = append(result.Deny, perms.Deny...)
			result.AdditionalDirectories = append(result.AdditionalDirectories, perms.AdditionalDirectories...)
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

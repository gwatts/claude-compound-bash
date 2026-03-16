// Package matcher implements Bash(...) pattern matching against extracted
// commands. Supports two formats:
//
//   - Bash(prefix:glob) — prefix matched literally, glob matched against remainder
//   - Bash(glob)        — glob matched against the full command string
//
// The glob uses fnmatch semantics where '*' matches any character including '/'.
package matcher

import (
	"strings"
)

// Pattern represents a parsed Bash(...) permission pattern.
type Pattern struct {
	// Raw is the original pattern string, e.g. "Bash(git add:*)".
	Raw string

	// For colon-delimited format:
	// Prefix is the command prefix before the colon, e.g. "git add".
	Prefix string
	// Glob is the glob portion after the colon, e.g. "*".
	Glob string

	// For non-colon format:
	// FullGlob is the entire inner string used as a glob against the full command.
	FullGlob string

	// MatchAll is true for "Bash(*)" — matches any command.
	MatchAll bool

	// HasColon indicates the pattern uses prefix:glob format.
	HasColon bool
}

// ParsePattern parses a permission string like "Bash(git add:*)" into a Pattern.
// Returns nil if the string is not a Bash(...) pattern.
func ParsePattern(s string) *Pattern {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "Bash(") || !strings.HasSuffix(s, ")") {
		return nil
	}
	inner := s[5 : len(s)-1] // strip "Bash(" and ")"
	if inner == "" {
		return nil
	}

	p := &Pattern{Raw: s}

	if inner == "*" {
		p.MatchAll = true
		p.FullGlob = "*"
		return p
	}

	// Split on the first colon to determine format.
	if idx := strings.Index(inner, ":"); idx >= 0 {
		p.HasColon = true
		p.Prefix = inner[:idx]
		p.Glob = inner[idx+1:]
	} else if containsGlobChar(inner) {
		// No colon but contains glob characters — treat entire string as glob.
		p.FullGlob = inner
	} else {
		// No colon, no glob chars — exact match.
		p.Prefix = inner
	}

	return p
}

// containsGlobChar reports whether s contains any glob metacharacters.
func containsGlobChar(s string) bool {
	return strings.ContainsAny(s, "*?[")
}

// Matches returns true if the given command string matches this pattern.
// The command is the full command line as a single string (e.g. "git add -A").
func (p *Pattern) Matches(command string) bool {
	if p.MatchAll {
		return true
	}

	// Non-colon glob format: match the full glob against the entire command.
	if p.FullGlob != "" {
		return globMatch(p.FullGlob, command)
	}

	// Exact match (no colon, no glob chars).
	if !p.HasColon {
		return command == p.Prefix
	}

	// Colon format: prefix:glob.
	if !strings.HasPrefix(command, p.Prefix) {
		return false
	}

	remainder := command[len(p.Prefix):]

	if p.Prefix != "" {
		if remainder == "" {
			// Command is exactly the prefix with no args.
			return globMatch(p.Glob, "")
		}
		if remainder[0] != ' ' {
			// e.g. prefix="git" but command="gitk" — not a match.
			return false
		}
		remainder = remainder[1:] // strip the separating space
	}

	return globMatch(p.Glob, remainder)
}

// MatchesAny returns true if the command matches any of the given patterns.
func MatchesAny(command string, patterns []Pattern) bool {
	for i := range patterns {
		if patterns[i].Matches(command) {
			return true
		}
	}
	return false
}

// ParsePatterns parses a slice of permission strings, returning only valid
// Bash(...) patterns.
func ParsePatterns(perms []string) []Pattern {
	var patterns []Pattern
	for _, s := range perms {
		if p := ParsePattern(s); p != nil {
			patterns = append(patterns, *p)
		}
	}
	return patterns
}

// globMatch matches a pattern against a string. Unlike filepath.Match,
// '*' matches any character including '/'. Supports '*', '?', and '[...]'.
func globMatch(pattern, name string) bool {
	for len(pattern) > 0 {
		switch pattern[0] {
		case '*':
			// Consume consecutive stars.
			for len(pattern) > 0 && pattern[0] == '*' {
				pattern = pattern[1:]
			}
			if len(pattern) == 0 {
				// Trailing * matches everything.
				return true
			}
			// Try matching the rest of the pattern at every position.
			for i := range len(name) + 1 {
				if globMatch(pattern, name[i:]) {
					return true
				}
			}
			return false

		case '?':
			if len(name) == 0 {
				return false
			}
			pattern = pattern[1:]
			name = name[1:]

		case '[':
			if len(name) == 0 {
				return false
			}
			// Find closing bracket.
			end := strings.Index(pattern[1:], "]")
			if end < 0 {
				// Malformed — treat '[' as literal.
				if name[0] != '[' {
					return false
				}
				pattern = pattern[1:]
				name = name[1:]
				continue
			}
			class := pattern[1 : end+1]
			pattern = pattern[end+2:]

			negate := false
			if len(class) > 0 && (class[0] == '!' || class[0] == '^') {
				negate = true
				class = class[1:]
			}

			matched := false
			ch := name[0]
			for i := 0; i < len(class); i++ {
				if i+2 < len(class) && class[i+1] == '-' {
					if ch >= class[i] && ch <= class[i+2] {
						matched = true
					}
					i += 2
				} else if class[i] == ch {
					matched = true
				}
			}
			if matched == negate {
				return false
			}
			name = name[1:]

		case '\\':
			// Escape next character.
			pattern = pattern[1:]
			if len(pattern) == 0 {
				return false
			}
			if len(name) == 0 || name[0] != pattern[0] {
				return false
			}
			pattern = pattern[1:]
			name = name[1:]

		default:
			if len(name) == 0 || name[0] != pattern[0] {
				return false
			}
			pattern = pattern[1:]
			name = name[1:]
		}
	}
	return len(name) == 0
}

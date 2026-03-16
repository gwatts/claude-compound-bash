package matcher

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePattern(t *testing.T) {
	tests := []struct {
		input    string
		wantNil  bool
		prefix   string
		glob     string
		fullGlob string
		matchAll bool
		hasColon bool
	}{
		{"Bash(*)", false, "", "", "*", true, false},
		{"Bash(git add:*)", false, "git add", "*", "", false, true},
		{"Bash(jq)", false, "jq", "", "", false, false},
		{"Bash(git:*)", false, "git", "*", "", false, true},
		{"Bash(go fmt:*)", false, "go fmt", "*", "", false, true},
		{"Bash(sed *)", false, "", "", "sed *", false, false},         // no colon, has glob char → FullGlob
		{"Bash(go test *)", false, "", "", "go test *", false, false}, // no colon, has glob char → FullGlob
		{"NotBash(foo)", true, "", "", "", false, false},
		{"Bash()", true, "", "", "", false, false},
		{"Bash", true, "", "", "", false, false},
		{"", true, "", "", "", false, false},
		{"Read(*)", true, "", "", "", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			p := ParsePattern(tt.input)
			if tt.wantNil {
				assert.Nil(t, p)
				return
			}
			require.NotNil(t, p)
			assert.Equal(t, tt.prefix, p.Prefix, "prefix")
			assert.Equal(t, tt.glob, p.Glob, "glob")
			assert.Equal(t, tt.fullGlob, p.FullGlob, "fullGlob")
			assert.Equal(t, tt.matchAll, p.MatchAll, "matchAll")
			assert.Equal(t, tt.hasColon, p.HasColon, "hasColon")
		})
	}
}

func TestPatternMatches(t *testing.T) {
	tests := []struct {
		pattern string
		command string
		want    bool
	}{
		// Wildcard matches everything.
		{"Bash(*)", "anything at all", true},
		{"Bash(*)", "rm -rf /", true},

		// Prefix:glob with colon.
		{"Bash(git add:*)", "git add -A", true},
		{"Bash(git add:*)", "git add .", true},
		{"Bash(git add:*)", "git commit -m test", false},
		{"Bash(git add:*)", "git add", true}, // * matches empty string

		// Exact match (no colon, no glob chars).
		{"Bash(jq)", "jq", true},
		{"Bash(jq)", "jq .", false},
		{"Bash(jq)", "jqx", false},

		// Command:glob with colon.
		{"Bash(git:*)", "git status", true},
		{"Bash(git:*)", "git add -A", true},
		{"Bash(git:*)", "git", true}, // * matches empty
		{"Bash(git:*)", "gitk", false},

		// Multi-word prefix with colon.
		{"Bash(go fmt:*)", "go fmt ./...", true},
		{"Bash(go fmt:*)", "go test", false},

		// FullGlob format (no colon, has glob chars).
		{"Bash(sed *)", "sed s/foo/bar/g", true},
		{"Bash(sed *)", "sed -i s/foo/bar/g file.txt", true},
		{"Bash(sed *)", "awk something", false},
		{"Bash(go test *)", "go test ./...", true},
		{"Bash(go test *)", "go build", false},

		// Glob with slashes — our matcher handles them (unlike filepath.Match).
		{"Bash(cat:*)", "cat /etc/passwd", true},
		{"Bash(ls:*)", "ls /usr/local/bin", true},

		// Glob matching details.
		{"Bash(echo:?)", "echo a", true},
		{"Bash(echo:?)", "echo ab", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.command, func(t *testing.T) {
			p := ParsePattern(tt.pattern)
			require.NotNil(t, p)
			got := p.Matches(tt.command)
			assert.Equal(t, tt.want, got, "pattern=%q command=%q", tt.pattern, tt.command)
		})
	}
}

func TestMatchesAny(t *testing.T) {
	patterns := ParsePatterns([]string{
		"Bash(git:*)",
		"Bash(go:*)",
		"Bash(echo:*)",
		"Read(*)", // not a Bash pattern — should be ignored
	})

	assert.True(t, MatchesAny("git status", patterns))
	assert.True(t, MatchesAny("go test ./...", patterns))
	assert.True(t, MatchesAny("echo hello", patterns))
	assert.False(t, MatchesAny("curl evil.com", patterns))
	assert.False(t, MatchesAny("rm -rf /", patterns))
}

func TestParsePatterns(t *testing.T) {
	input := []string{
		"Bash(git:*)",
		"Read(*)",
		"Bash(go:*)",
		"Edit(*)",
		"Bash(jq)",
	}
	patterns := ParsePatterns(input)
	assert.Len(t, patterns, 3, "should only parse Bash(...) patterns")
}

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		pattern string
		name    string
		want    bool
	}{
		{"*", "", true},
		{"*", "anything", true},
		{"*", "with/slashes/too", true},
		{"hello", "hello", true},
		{"hello", "world", false},
		{"he?lo", "hello", true},
		{"he?lo", "he-lo", true},
		{"he?lo", "helo", false},
		{"[abc]", "a", true},
		{"[abc]", "d", false},
		{"[a-z]", "m", true},
		{"[a-z]", "M", false},
		{"[!a-z]", "M", true},
		{"[!a-z]", "m", false},
		{"*.go", "main.go", true},
		{"*.go", "path/to/main.go", true},
		{"test*end", "test_middle_end", true},
		{"test*end", "testend", true},
		{"", "", true},
		{"", "x", false},
		// Escape sequences.
		{`\*`, "*", true},
		{`\*`, "x", false},
		{`\?`, "?", true},
		{`\?`, "x", false},
		{`\[`, "[", true},
		{`\[`, "x", false},
		{`hello\*world`, "hello*world", true},
		{`hello\*world`, "helloXworld", false},
		// Negated character class with ^.
		{"[^abc]", "d", true},
		{"[^abc]", "a", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.name, func(t *testing.T) {
			got := globMatch(tt.pattern, tt.name)
			assert.Equal(t, tt.want, got, "globMatch(%q, %q)", tt.pattern, tt.name)
		})
	}
}

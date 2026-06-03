package parser

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parseSingle parses a command expected to yield exactly one extracted command.
func parseSingle(t *testing.T, src string) Command {
	t.Helper()
	res, err := Parse(src)
	require.NoError(t, err)
	require.Len(t, res.Commands, 1)
	return res.Commands[0]
}

func TestWrapperInnerXargs(t *testing.T) {
	tests := []struct {
		name      string
		src       string
		wantNames []string
	}{
		{"plain", "xargs grep -l foo", []string{"grep"}},
		{"null and count flags", "xargs -0 -n1 grep -l foo", []string{"grep"}},
		{"attached replace", "xargs -I{} basename {}", []string{"basename"}},
		{"separate replace arg", "xargs -I {} cp {} dest", []string{"cp"}},
		{"separate count arg", "xargs -n 1 head", []string{"head"}},
		{"double dash", "xargs -0 -- rm -rf", []string{"rm"}},
		{"long opt with equals", "xargs --max-args=5 grep x", []string{"grep"}},
		{"long opt separate arg", "xargs --max-args 5 grep x", []string{"grep"}},
		{"dangerous payload still extracted", "xargs rm -rf", []string{"rm"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inners, isWrapper := WrapperInner(parseSingle(t, tt.src))
			assert.True(t, isWrapper)
			require.Len(t, inners, len(tt.wantNames))
			for i, want := range tt.wantNames {
				assert.Equal(t, want, inners[i].Name)
			}
		})
	}
}

func TestWrapperInnerXargsNoPayload(t *testing.T) {
	// Recognized wrapper, but no command word — caller must fail closed.
	for _, src := range []string{"xargs", "xargs -0", "xargs -n 1"} {
		inners, isWrapper := WrapperInner(parseSingle(t, src))
		assert.True(t, isWrapper, src)
		assert.Empty(t, inners, src)
	}
}

func TestWrapperInnerFindExec(t *testing.T) {
	tests := []struct {
		name      string
		src       string
		wantNames []string
	}{
		{"exec semicolon", `find . -name '*.go' -exec grep -l foo {} \;`, []string{"grep"}},
		{"exec plus", `find . -name '*.go' -exec grep X {} +`, []string{"grep"}},
		{"execdir", `find . -type f -execdir cat {} \;`, []string{"cat"}},
		{"multiple exec", `find . -exec grep X {} \; -exec rm {} \;`, []string{"grep", "rm"}},
		{"dangerous payload still extracted", `find . -exec rm -rf {} \;`, []string{"rm"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inners, isWrapper := WrapperInner(parseSingle(t, tt.src))
			assert.True(t, isWrapper)
			require.Len(t, inners, len(tt.wantNames))
			for i, want := range tt.wantNames {
				assert.Equal(t, want, inners[i].Name)
			}
		})
	}
}

func TestWrapperInnerFindExecLiteralPlus(t *testing.T) {
	// A "+" that is not the batching terminator (i.e. not right after "{}") is a
	// literal argument and must stay in the payload, so deny/ask rules still see
	// the full command line.
	inners, isWrapper := WrapperInner(parseSingle(t, `find . -exec grep + /etc/shadow {} \;`))
	assert.True(t, isWrapper)
	require.Len(t, inners, 1)
	assert.Equal(t, "grep", inners[0].Name)
	assert.Equal(t, "grep + /etc/shadow {}", strings.Join(inners[0].Args, " "))
}

func TestWrapperInnerFindExecBatchingPlus(t *testing.T) {
	// A "+" right after "{}" is the real batching terminator.
	inners, isWrapper := WrapperInner(parseSingle(t, `find . -exec grep -l foo {} +`))
	assert.True(t, isWrapper)
	require.Len(t, inners, 1)
	assert.Equal(t, "grep -l foo {}", strings.Join(inners[0].Args, " "))
}

func TestFindHasMutatingActionIgnoresExecPayload(t *testing.T) {
	// A token equal to a mutating primary but living inside an -exec payload is
	// passed to the command, not interpreted by find — it must not be flagged.
	for _, src := range []string{
		`find . -exec grep -e -delete {} \;`,
		`find . -exec grep -delete {} \; -name '*.go'`,
		`find . -execdir sed -fls {} \;`,
	} {
		assert.False(t, FindHasMutatingNonExecAction(parseSingle(t, src)), src)
	}
}

func TestFindHasMutatingActionDetectsRealActions(t *testing.T) {
	// Real top-level actions — including one that follows an -exec payload — are
	// still detected.
	for _, src := range []string{
		`find . -delete -exec grep X {} \;`,
		`find . -exec grep X {} \; -delete`,
		`find . -exec grep X {} \; -fprintf /tmp/o %p`,
	} {
		assert.True(t, FindHasMutatingNonExecAction(parseSingle(t, src)), src)
	}
}

func TestWrapperInnerFindOkIsWrapper(t *testing.T) {
	// -ok/-okdir run a command but have no payload we validate, and no -exec, so
	// they must enter the wrapper path (fail closed) rather than fall through to
	// a generic find allow.
	for _, src := range []string{
		`find . -ok rm {} \;`,
		`find . -okdir rm {} \;`,
	} {
		inners, isWrapper := WrapperInner(parseSingle(t, src))
		assert.True(t, isWrapper, src)
		assert.Empty(t, inners, src)
	}
}

func TestWrapperInnerPlainFindNotWrapper(t *testing.T) {
	// A read-only find (no -exec, no mutating action) is not a wrapper.
	for _, src := range []string{
		`find . -name '*.go'`,
		`find . -type f -print`,
	} {
		_, isWrapper := WrapperInner(parseSingle(t, src))
		assert.False(t, isWrapper, src)
	}
}

func TestWrapperInnerFindDeleteIsWrapper(t *testing.T) {
	// A mutating action with no -exec payload must fail closed via the wrapper
	// path rather than ride a generic find allow.
	inners, isWrapper := WrapperInner(parseSingle(t, `find . -type f -delete`))
	assert.True(t, isWrapper)
	assert.Empty(t, inners)
}

func TestWrapperInnerNotAWrapper(t *testing.T) {
	for _, src := range []string{"grep foo", "ls -la", "git status"} {
		_, isWrapper := WrapperInner(parseSingle(t, src))
		assert.False(t, isWrapper, src)
	}
}

func TestWrapperInnerDynamicPayload(t *testing.T) {
	// xargs $CMD — the payload name is a variable, so it must be flagged dynamic
	// and never matched against a static allow rule.
	inners, isWrapper := WrapperInner(parseSingle(t, "xargs $CMD foo"))
	assert.True(t, isWrapper)
	require.Len(t, inners, 1)
	assert.True(t, inners[0].Dynamic)
	assert.Empty(t, inners[0].Name)
}

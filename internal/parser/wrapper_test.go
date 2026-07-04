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
		// Clustered short options with a value-taking option at the end: the value
		// may be attached ("-0n1") or the following token ("-0n 1"). Either way the
		// command is what follows, not the option value.
		{"cluster attached value", "xargs -0n1 rm -rf", []string{"rm"}},
		{"cluster separate value", "xargs -0n 1 rm -rf", []string{"rm"}},
		{"cluster boolean then count", "xargs -rn 1 grep x", []string{"grep"}},
		{"bsd replsize separate", "xargs -S 999 rm -rf", []string{"rm"}},
		{"bsd replsize cluster", "xargs -0S 4096 rm", []string{"rm"}},
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

func TestWrapperInnerXargsAppendsArgs(t *testing.T) {
	tests := []struct {
		name        string
		src         string
		wantAppends bool
	}{
		{"plain xargs appends", "xargs rm -rf", true},
		{"with count flag appends", "xargs -n1 rm", true},
		{"null-delimited appends", "xargs -0 grep foo", true},
		{"replace -I substitutes", "xargs -I{} rm {}", false},
		{"replace -I attached", "xargs -I{} grep {} file", false},
		{"replace -J substitutes", "xargs -J% cp % dest", false},
		{"replace deprecated -i", "xargs -i cp {} dest", false},
		{"replace long form", "xargs --replace=% cp % dest", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inners, isWrapper := WrapperInner(parseSingle(t, tt.src))
			assert.True(t, isWrapper)
			require.Len(t, inners, 1)
			assert.Equal(t, tt.wantAppends, inners[0].AppendsArgs)
		})
	}
}

func TestWrapperInnerNonXargsDoesNotAppend(t *testing.T) {
	// find -exec substitutes {} and process wrappers run a static command; none
	// append invisible runtime tokens, so AppendsArgs stays false.
	for _, src := range []string{
		`find . -exec grep X {} \;`,
		`find . -exec rm {} +`,
		"timeout 30 rm -rf /x",
		"nice make",
	} {
		inners, isWrapper := WrapperInner(parseSingle(t, src))
		require.True(t, isWrapper, src)
		require.NotEmpty(t, inners, src)
		for _, in := range inners {
			assert.Falsef(t, in.AppendsArgs, "src %q inner %q", src, in.Name)
		}
	}
}

func TestWrapperInnerProcessWrappers(t *testing.T) {
	tests := []struct {
		name     string
		src      string
		wantName string
		wantArgs []string
	}{
		{"timeout duration", "timeout 30 npm test", "npm", []string{"npm", "test"}},
		{"timeout signal separate", "timeout -s KILL 30 rm -rf /x", "rm", []string{"rm", "-rf", "/x"}},
		{"timeout signal attached", "timeout -sKILL 30 grep foo", "grep", []string{"grep", "foo"}},
		{"timeout kill-after", "timeout -k 5 30 make", "make", []string{"make"}},
		{"timeout boolean opt", "timeout --preserve-status 5 make", "make", []string{"make"}},
		{"timeout long signal equals", "timeout --signal=TERM 5 make", "make", []string{"make"}},
		{"timeout double dash", "timeout -- 30 make", "make", []string{"make"}},
		{"nice bare", "nice make", "make", []string{"make"}},
		{"nice -n separate", "nice -n 10 make", "make", []string{"make"}},
		{"nice -n attached", "nice -n10 make", "make", []string{"make"}},
		{"nice numeric", "nice -10 make", "make", []string{"make"}},
		{"nice long adjustment", "nice --adjustment=5 make", "make", []string{"make"}},
		{"nohup", "nohup ./server --port 80", "./server", []string{"./server", "--port", "80"}},
		{"nohup double dash", "nohup -- ./server", "./server", []string{"./server"}},
		{"stdbuf attached", "stdbuf -oL -eL grep foo", "grep", []string{"grep", "foo"}},
		{"stdbuf separate", "stdbuf -o L grep foo", "grep", []string{"grep", "foo"}},
		{"stdbuf long", "stdbuf --output=L grep foo", "grep", []string{"grep", "foo"}},
		{"dangerous payload still extracted", "timeout 5 rm -rf /x", "rm", []string{"rm", "-rf", "/x"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inners, isWrapper := WrapperInner(parseSingle(t, tt.src))
			assert.True(t, isWrapper)
			require.Len(t, inners, 1)
			assert.Equal(t, tt.wantName, inners[0].Name)
			assert.Equal(t, tt.wantArgs, inners[0].Args)
		})
	}
}

func TestWrapperInnerProcessWrappersNoPayload(t *testing.T) {
	// Recognized wrapper, but no inner command word — caller must fail closed.
	for _, src := range []string{
		"nohup", "nice", "nice -n 10", "stdbuf -oL", "timeout 30", "timeout -s KILL 30",
	} {
		inners, isWrapper := WrapperInner(parseSingle(t, src))
		assert.True(t, isWrapper, src)
		assert.Empty(t, inners, src)
	}
}

func TestWrapperInnerTimeIsTransparentInParser(t *testing.T) {
	// bash's `time` reserved word never reaches WrapperInner as a command named
	// "time"; the parser yields the inner command directly.
	cmd := parseSingle(t, "time npm test")
	assert.Equal(t, "npm", cmd.Name)
	_, isWrapper := WrapperInner(cmd)
	assert.False(t, isWrapper, "the inner npm command is not itself a wrapper")
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

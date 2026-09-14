package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// outputPathRedirect returns the first output redirect with a file target
// (skipping heredocs and fd-to-fd duplications), failing if there is none.
func outputPathRedirect(t *testing.T, rs []RedirectInfo) RedirectInfo {
	t.Helper()
	for _, r := range rs {
		if r.IsOutput() && !r.IsHeredoc && !r.IsFDDup() {
			return r
		}
	}
	t.Fatalf("no output path redirect found in %+v", rs)
	return RedirectInfo{}
}

func TestExpandRedirectTargetVars(t *testing.T) {
	tests := []struct {
		name    string
		cmd     string
		literal bool   // expected TargetLiteral after expansion
		target  string // expected Target when literal (ignored otherwise)
	}{
		// --- resolved cases ---
		{
			name:    "quoted var with suffix",
			cmd:     `SCRATCH=/private/tmp/claude-501/s; echo hi > "$SCRATCH/out.txt"`,
			literal: true,
			target:  "/private/tmp/claude-501/s/out.txt",
		},
		{
			name:    "unquoted var with suffix",
			cmd:     `SCRATCH=/private/tmp/s; echo hi > $SCRATCH/out.txt`,
			literal: true,
			target:  "/private/tmp/s/out.txt",
		},
		{
			name:    "braced var",
			cmd:     `SCRATCH=/tmp/s; echo hi > "${SCRATCH}/out.txt"`,
			literal: true,
			target:  "/tmp/s/out.txt",
		},
		{
			name:    "append redirect",
			cmd:     `S=/tmp/s; echo hi >> "$S/log"`,
			literal: true,
			target:  "/tmp/s/log",
		},
		{
			name:    "heredoc alongside path redirect",
			cmd:     "S=/tmp/s; cat > \"$S/candidates.txt\" <<'EOF'\nx\nEOF",
			literal: true,
			target:  "/tmp/s/candidates.txt",
		},
		{
			name:    "two vars in one path",
			cmd:     `A=/tmp; B=sub; echo hi > "$A/$B/out"`,
			literal: true,
			target:  "/tmp/sub/out",
		},
		{
			name:    "reassignment uses latest prior value",
			cmd:     `S=/tmp/a; S=/tmp/b; echo hi > "$S/out"`,
			literal: true,
			target:  "/tmp/b/out",
		},
		{
			name:    "assignment persists across an intervening command",
			cmd:     `S=/tmp/s; mkdir -p "$S"; cd /somewhere; echo hi > "$S/out"`,
			literal: true,
			target:  "/tmp/s/out",
		},
		{
			name:    "var value is fully literal path",
			cmd:     `S=/tmp/s; echo hi > "$S"`,
			literal: true,
			target:  "/tmp/s",
		},
		{
			name:    "assignment as && left operand runs first",
			cmd:     `S=/tmp/s && echo hi > "$S/out"`,
			literal: true,
			target:  "/tmp/s/out",
		},
		{
			name:    "chained && assignments before command",
			cmd:     `A=/tmp && B=sub && echo hi > "$A/$B/out"`,
			literal: true,
			target:  "/tmp/sub/out",
		},
		{
			name:    "assignment as || left operand still runs",
			cmd:     `S=/tmp/s || true; echo hi > "$S/out"`,
			literal: true,
			target:  "/tmp/s/out",
		},
		{
			name:    "&& assignment then redirect inside a pipeline",
			cmd:     `S=/tmp/s && cat in.txt | grep foo > "$S/out"`,
			literal: true,
			target:  "/tmp/s/out",
		},
		{
			name:    "backgrounded && chain resolves within the same unit",
			cmd:     `S=/tmp/s && swift test > "$S/out.log" 2>&1 & echo started`,
			literal: true,
			target:  "/tmp/s/out.log",
		},
		{
			name:    "redirect inside a subshell sees the subshell assignment",
			cmd:     `(S=/tmp/s; echo hi > "$S/out")`,
			literal: true,
			target:  "/tmp/s/out",
		},
		{
			name:    "backgrounded subshell redirect resolves",
			cmd:     `(S=/tmp/s && echo hi > "$S/out") &`,
			literal: true,
			target:  "/tmp/s/out",
		},
		{
			// The assignment is gated behind `cd` by `&&`, but the redirect is
			// on the same `&&` spine — reaching it implies the assignment ran.
			name:    "&& chain: assignment gated behind a command, redirect on the same spine",
			cmd:     `cd /valid && S=/tmp/s && go test ./... > "$S/out.log" 2>&1`,
			literal: true,
			target:  "/tmp/s/out.log",
		},
		{
			name:    "&& chain: multiple fallible commands before the gated assignment",
			cmd:     `cd /valid && make && S=/tmp/s && cmd > "$S/out"`,
			literal: true,
			target:  "/tmp/s/out",
		},
		{
			name:    "&& chain: gated assignment resolves a redirect inside a later subshell operand",
			cmd:     `cd /valid && (S=/tmp/s && echo hi > "$S/out")`,
			literal: true,
			target:  "/tmp/s/out",
		},

		// --- deliberately left dynamic (unsound or unresolvable) ---
		{
			// A gated assignment holds only within its `&&` chain; the redirect
			// after `;` runs even when `cd` fails and $S is never set (bash would
			// expand it to "/leak"). This is the case0 shape from the worktree
			// test command; it must stay dynamic.
			name:    "gated && assignment does not leak past its chain to a later statement",
			cmd:     `cd /valid && S=/tmp/s && cmd; echo hi > "$S/leak"`,
			literal: false,
		},
		{
			name:    "|| earlier in the spine breaks the gated-chain guarantee",
			cmd:     `a || S=/tmp/s && cmd > "$S/out"`,
			literal: false,
		},
		{
			name:    "|| after the assignment breaks the gated-chain guarantee",
			cmd:     `cmd1 && S=/tmp/s || cmd2 > "$S/out"`,
			literal: false,
		},
		{
			name:    "use before assignment",
			cmd:     `echo hi > "$S/out"; S=/tmp/s`,
			literal: false,
		},
		{
			name:    "command-prefix assignment does not persist",
			cmd:     `S=/tmp/s echo hi > "$S/out"`,
			literal: false,
		},
		{
			name:    "assignment inside subshell does not escape",
			cmd:     `(S=/tmp/s); echo hi > "$S/out"`,
			literal: false,
		},
		{
			name:    "backgrounded assignment does not leak to a later statement",
			cmd:     `S=/tmp/s & echo hi > "$S/out"`,
			literal: false,
		},
		{
			name:    "assignment inside if body is conditional",
			cmd:     `if true; then S=/tmp/s; fi; echo hi > "$S/out"`,
			literal: false,
		},
		{
			name:    "conditional && right operand may not run",
			cmd:     `grep -q foo bar && S=/tmp/s; echo hi > "$S/out"`,
			literal: false,
		},
		{
			name:    "conditional reassignment after safe assignment is not trusted",
			cmd:     `S=/tmp/s; grep -q x y || S=/other; echo hi > "$S/out"`,
			literal: false,
		},
		{
			name:    "reassignment inside if body is not trusted",
			cmd:     `S=/tmp/s; if foo; then S=/other; fi; echo hi > "$S/out"`,
			literal: false,
		},
		{
			name:    "dynamic assignment value",
			cmd:     `S=$(pwd); echo hi > "$S/out"`,
			literal: false,
		},
		{
			name:    "variable chaining is not resolved",
			cmd:     `A=/tmp; S=$A/s; echo hi > "$S/out"`,
			literal: false,
		},
		{
			name:    "unknown variable",
			cmd:     `echo hi > "$UNSET/out"`,
			literal: false,
		},
		{
			name:    "param modifier is not a plain reference",
			cmd:     `S=/tmp/s; echo hi > "${S:-/other}/out"`,
			literal: false,
		},
		{
			name:    "tilde value would be expanded by bash",
			cmd:     `S=~/scratch; echo hi > "$S/out"`,
			literal: false,
		},
		{
			name:    "glob in resolved target stays dynamic",
			cmd:     `S=/tmp/s; echo hi > $S/*.log`,
			literal: false,
		},
		{
			name:    "export assignment is not yet resolved",
			cmd:     `export S=/tmp/s; echo hi > "$S/out"`,
			literal: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Parse(tt.cmd)
			require.NoError(t, err)
			r := outputPathRedirect(t, result.Redirects)

			assert.Equal(t, tt.literal, r.TargetLiteral, "TargetLiteral for %q", tt.cmd)
			if tt.literal {
				assert.Equal(t, tt.target, r.Target, "expanded target for %q", tt.cmd)
				assert.Equal(t, RedirectCheckPath, ClassifyRedirect(&r),
					"resolved target should be path-checked, not asked")
			} else {
				assert.Equal(t, RedirectAsk, ClassifyRedirect(&r),
					"unresolved dynamic target should be asked")
			}
		})
	}
}

// TestExpandRedirectPreservesRaw verifies that resolving a variable keeps the
// original source text in Raw (for logs and prompts) while only the resolved
// path lands in Target.
func TestExpandRedirectPreservesRaw(t *testing.T) {
	result, err := Parse(`S=/tmp/s; echo hi > "$S/out.txt"`)
	require.NoError(t, err)
	r := outputPathRedirect(t, result.Redirects)
	assert.Equal(t, "/tmp/s/out.txt", r.Target)
	assert.Equal(t, `>"$S/out.txt"`, r.Raw, "Raw keeps the unexpanded source")
}

// TestExpandRedirectIntoScratchpad is the end-to-end payoff: a redirect that
// writes into the Claude Code scratchpad via a variable resolves to a path that
// the normal allow-dir check accepts, so it no longer forces a prompt.
func TestExpandRedirectIntoScratchpad(t *testing.T) {
	scratch := "/tmp/claude-501/session/scratchpad"
	result, err := Parse(`S=` + scratch + `; echo hi > "$S/out.log"`)
	require.NoError(t, err)
	r := outputPathRedirect(t, result.Redirects)

	require.True(t, r.TargetLiteral, "variable should resolve to a literal path")
	require.Equal(t, RedirectCheckPath, ClassifyRedirect(&r))

	allowed, err := ExpandAdditionalDirs([]string{scratch})
	require.NoError(t, err)
	resolved, err := ResolvePath(r.Target, "/nonexistent-cwd")
	require.NoError(t, err)
	assert.True(t, IsInsideAllowedDir(resolved, "/nonexistent-cwd", allowed),
		"resolved scratchpad redirect is inside the allowed tree")
}

// TestExpandRedirectLiteralUnaffected guards that a plainly literal target is
// unchanged by the expansion path.
func TestExpandRedirectLiteralUnaffected(t *testing.T) {
	result, err := Parse(`echo hi > output.txt`)
	require.NoError(t, err)
	r := outputPathRedirect(t, result.Redirects)
	assert.True(t, r.TargetLiteral)
	assert.Equal(t, "output.txt", r.Target)
}

// TestExpandRedirectIntrinsicTMPDIR covers resolving $TMPDIR from the inherited
// environment, and the guard that suppresses it whenever the command touches
// the variable itself.
func TestExpandRedirectIntrinsicTMPDIR(t *testing.T) {
	tests := []struct {
		name    string
		tmpdir  string // TMPDIR env value ("" means unset)
		cmd     string
		literal bool
		target  string
	}{
		{
			name:    "plain intrinsic expansion",
			tmpdir:  "/var/tmpdir",
			cmd:     `echo hi > "$TMPDIR/out.log"`,
			literal: true,
			target:  "/var/tmpdir/out.log",
		},
		{
			name:    "trailing slash is normalized",
			tmpdir:  "/var/tmpdir/",
			cmd:     `echo hi > "$TMPDIR/out.log"`,
			literal: true,
			target:  "/var/tmpdir/out.log",
		},
		{
			name:    "in-command literal assignment wins over env",
			tmpdir:  "/var/tmpdir",
			cmd:     `TMPDIR=/tmp/mine; echo hi > "$TMPDIR/out"`,
			literal: true,
			target:  "/tmp/mine/out",
		},
		{
			name:    "unset in env leaves target dynamic",
			tmpdir:  "",
			cmd:     `echo hi > "$TMPDIR/out"`,
			literal: false,
		},
		{
			name:    "export reassignment suppresses intrinsic",
			tmpdir:  "/var/tmpdir",
			cmd:     `export TMPDIR=/etc; echo hi > "$TMPDIR/passwd"`,
			literal: false,
		},
		{
			name:    "dynamic reassignment suppresses intrinsic",
			tmpdir:  "/var/tmpdir",
			cmd:     `TMPDIR=$(pwd); echo hi > "$TMPDIR/out"`,
			literal: false,
		},
		{
			name:    "unset suppresses intrinsic",
			tmpdir:  "/var/tmpdir",
			cmd:     `unset TMPDIR; echo hi > "$TMPDIR/out"`,
			literal: false,
		},
		{
			name:    "function-body assignment suppresses intrinsic",
			tmpdir:  "/var/tmpdir",
			cmd:     `f() { TMPDIR=/etc; }; f; echo hi > "$TMPDIR/out"`,
			literal: false,
		},
		{
			name:    "subshell reassignment does not escape, intrinsic still applies",
			tmpdir:  "/var/tmpdir",
			cmd:     `(TMPDIR=/etc); echo hi > "$TMPDIR/out"`,
			literal: true,
			target:  "/var/tmpdir/out", // subshell TMPDIR=/etc doesn't leak; env value used
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("TMPDIR", tt.tmpdir)
			result, err := Parse(tt.cmd)
			require.NoError(t, err)
			r := outputPathRedirect(t, result.Redirects)
			assert.Equal(t, tt.literal, r.TargetLiteral, "TargetLiteral for %q", tt.cmd)
			if tt.literal {
				assert.Equal(t, tt.target, r.Target, "expanded target for %q", tt.cmd)
			}
		})
	}
}

// TestExpandRedirectIntrinsicHOME covers the trusted-directory scenario: the
// model writes "$HOME/logs/…" while the allow list holds the literal expansion.
func TestExpandRedirectIntrinsicHOME(t *testing.T) {
	t.Setenv("HOME", "/Users/joe")

	result, err := Parse(`echo hi > "$HOME/logs/app.log"`)
	require.NoError(t, err)
	r := outputPathRedirect(t, result.Redirects)
	assert.True(t, r.TargetLiteral)
	assert.Equal(t, "/Users/joe/logs/app.log", r.Target)

	// A command that reassigns HOME must not be resolved from the stale env.
	result, err = Parse(`HOME=/tmp/fake echo hi > "$HOME/logs/app.log"`)
	require.NoError(t, err)
	r = outputPathRedirect(t, result.Redirects)
	assert.False(t, r.TargetLiteral, "prefix reassignment of HOME suppresses intrinsic")
}

// TestExpandRedirectReportedCommand covers the real reported shape: a scratch
// dir assigned with `&&`, a build redirected into it with `2>&1`, then follow-up
// statements that read the same file back.
func TestExpandRedirectReportedCommand(t *testing.T) {
	cmd := `SCRATCH=/private/tmp/claude-501/proj/sess/scratchpad && ` +
		`swift build --disable-automatic-resolution > "$SCRATCH/build2.log" 2>&1; ` +
		`echo "EXIT:$?"; grep -c "error:" "$SCRATCH/build2.log"`
	result, err := Parse(cmd)
	require.NoError(t, err)
	r := outputPathRedirect(t, result.Redirects)
	assert.True(t, r.TargetLiteral, "the && scratch assignment should resolve the redirect")
	assert.Equal(t, "/private/tmp/claude-501/proj/sess/scratchpad/build2.log", r.Target)
}

// TestExpandRedirectMultiAssignStatement verifies that several standalone
// assignments sharing one statement (`A=/x B=/y`) are all recorded.
func TestExpandRedirectMultiAssignStatement(t *testing.T) {
	result, err := Parse(`A=/x B=/y; echo hi > "$A$B/out"`)
	require.NoError(t, err)
	r := outputPathRedirect(t, result.Redirects)
	assert.True(t, r.TargetLiteral)
	assert.Equal(t, "/x/y/out", r.Target)
}

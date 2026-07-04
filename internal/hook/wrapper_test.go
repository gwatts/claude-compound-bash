package hook

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// bash builds a Bash hook input for the given command string.
func bash(cmd string) *HookInput {
	return &HookInput{ToolName: "Bash", ToolInput: ToolInput{Command: cmd}}
}

func TestWrapperXargsAllowsSafePayload(t *testing.T) {
	allow := patterns("Bash(grep:*)", "Bash(rg:*)")
	tests := []string{
		`rg --files | xargs grep -l "Foo"`,
		`rg --files | xargs -0 grep -l bar`,
		`rg --files | xargs -I{} grep -l baz {}`,
	}
	for _, cmd := range tests {
		result := Process(bash(cmd), allow, nil, nil, nil, nopLog())
		assert.Equalf(t, ResultAllowed, result.Kind, "cmd: %s (%s)", cmd, result.Reason)
	}
}

func TestWrapperXargsDefersDangerousPayload(t *testing.T) {
	allow := patterns("Bash(grep:*)", "Bash(rg:*)")
	// rm is not allow-listed, so the hook can't approve it — defer to native.
	result := Process(bash(`rg --files | xargs rm -rf`), allow, nil, nil, nil, nopLog())
	assert.Equal(t, ResultDefer, result.Kind)
}

func TestWrapperXargsRespectsDenyAndAsk(t *testing.T) {
	allow := patterns("Bash(grep:*)")
	deny := patterns("Bash(grep --secret:*)")
	// Deny on the inner command must win even through the wrapper.
	result := Process(bash(`echo x | xargs grep --secret foo`), allow, nil, deny, nil, nopLog())
	assert.Equal(t, ResultDenyRule, result.Kind)
}

func TestWrapperDenyPayloadBeatsAskOnWrapper(t *testing.T) {
	// Regression: an ask rule matching the wrapper itself must not downgrade a
	// denied payload to an ask — deny always wins.
	allow := patterns("Bash(grep:*)")
	ask := patterns("Bash(xargs *)")
	deny := patterns("Bash(rm:*)")

	denied := Process(bash(`echo f | xargs rm -f`), allow, ask, deny, nil, nopLog())
	assert.Equal(t, ResultDenyRule, denied.Kind, "xargs rm must be cancelled, not asked")

	// A safe payload under the same ask-on-wrapper rule should still ask.
	asked := Process(bash(`echo f | xargs grep -l foo`), allow, ask, deny, nil, nopLog())
	assert.Equal(t, ResultAsk, asked.Kind, "ask rule on the wrapper itself is honored for non-denied payloads")
}

func TestWrapperFindExecDenyPayloadBeatsAsk(t *testing.T) {
	allow := patterns("Bash(grep:*)", "Bash(find *)")
	ask := patterns("Bash(find * -exec *)")
	deny := patterns("Bash(rm:*)")
	// Even with both an ask rule on `find -exec` and a generic find allow, an
	// -exec rm payload must be denied.
	result := Process(bash(`find . -exec rm {} \;`), allow, ask, deny, nil, nopLog())
	assert.Equal(t, ResultDenyRule, result.Kind)
}

func TestProcessWrapperAllowsApprovedInner(t *testing.T) {
	allow := patterns("Bash(npm test *)", "Bash(make *)", "Bash(grep:*)")
	tests := []string{
		`timeout 30 npm test --coverage`,
		`nice -n 10 make build`,
		`nohup make build`,
		`stdbuf -oL -eL grep foo`,
		`time npm test --coverage`, // bash reserved word: parser unwraps to `npm test`
	}
	for _, cmd := range tests {
		result := Process(bash(cmd), allow, nil, nil, nil, nopLog())
		assert.Equalf(t, ResultAllowed, result.Kind, "cmd: %s (%s)", cmd, result.Reason)
	}
}

func TestProcessWrapperDefersUnapprovedInner(t *testing.T) {
	// The wrapper is transparent: an inner command with no allow rule can't be
	// approved, so the hook defers rather than auto-allow on the wrapper's name.
	allow := patterns("Bash(npm test *)")
	result := Process(bash(`timeout 30 rm -rf /x`), allow, nil, nil, nil, nopLog())
	assert.Equal(t, ResultDefer, result.Kind)
}

func TestProcessWrapperDenyPayloadStillDenied(t *testing.T) {
	// Prefixing a denied command with an exec wrapper must not evade the deny —
	// the deny scan looks through the wrapper.
	allow := patterns("Bash(npm test *)")
	deny := patterns("Bash(rm:*)")
	for _, cmd := range []string{
		`timeout 30 rm -rf /x`,
		`nice -n 10 rm -rf /x`,
		`nohup rm -rf /x`,
		`stdbuf -oL rm -rf /x`,
	} {
		result := Process(bash(cmd), allow, nil, deny, nil, nopLog())
		assert.Equalf(t, ResultDenyRule, result.Kind, "cmd: %s (%s)", cmd, result.Reason)
	}
}

func TestProcessWrapperNestedWithOtherWrappers(t *testing.T) {
	// Exec wrappers compose with the xargs/find wrappers, and the deny scan sees
	// through the whole stack.
	allow := patterns("Bash(grep:*)")
	deny := patterns("Bash(rm:*)")

	// A safe inner stays quiet through stacked wrappers.
	ok := Process(bash(`rg --files | xargs nice grep -l foo`), append(allow, patterns("Bash(rg:*)")...), nil, nil, nil, nopLog())
	assert.Equalf(t, ResultAllowed, ok.Kind, "reason: %s", ok.Reason)

	// A denied inner is caught through find -exec + timeout.
	denied := Process(bash(`find . -exec timeout 5 rm {} \;`), allow, nil, deny, nil, nopLog())
	assert.Equal(t, ResultDenyRule, denied.Kind)
}

func TestWrapperXargsAppendedArgsNotApprovedByExactRule(t *testing.T) {
	// xargs appends stdin-derived tokens to the payload, so `xargs rm /tmp/safe`
	// really runs `rm /tmp/safe <stdin...>`. An exact allow rule for the static
	// form must NOT approve it — otherwise a narrow rule would green-light deleting
	// files it never named. The hook defers so native prompts.
	exact := patterns("Bash(rm /tmp/safe)")
	deferCases := []string{
		`printf '/tmp/important\n' | xargs rm /tmp/safe`,
		`printf '/tmp/important\n' | xargs -n1 rm /tmp/safe`, // flagged: native wouldn't strip this
		`printf 'x\n' | xargs timeout 5 rm /tmp/safe`,        // append flag propagates through timeout
	}
	for _, cmd := range deferCases {
		result := Process(bash(cmd), exact, nil, nil, nil, nopLog())
		assert.Equalf(t, ResultDefer, result.Kind, "cmd: %s (%s)", cmd, result.Reason)
	}

	// A trailing-wildcard rule DOES tolerate the appended args, so it still allows
	// — the `xargs grep` quality-of-life case is preserved.
	wild := patterns("Bash(rm /tmp/safe*)", "Bash(grep:*)", "Bash(rg:*)")
	for _, cmd := range []string{
		`printf '/tmp/important\n' | xargs rm /tmp/safe`,
		`rg --files | xargs grep -l foo`,
		`rg --files | xargs -n1 grep -l foo`,
	} {
		result := Process(bash(cmd), wild, nil, nil, nil, nopLog())
		assert.Equalf(t, ResultAllowed, result.Kind, "cmd: %s (%s)", cmd, result.Reason)
	}
}

func TestWrapperXargsReplaceModeUsesStaticMatch(t *testing.T) {
	// In -I/-J replace mode xargs substitutes at a visible placeholder instead of
	// appending, so the static command is matched as-is (like find -exec {}).
	allow := patterns("Bash(grep {} file)")
	// printf is an inert safe builtin, so only the grep payload needs a rule.
	result := Process(bash(`printf 'x\n' | xargs -I{} grep {} file`), allow, nil, nil, nil, nopLog())
	assert.Equalf(t, ResultAllowed, result.Kind, "reason: %s", result.Reason)
}

func TestWrapperXargsAppendedArgsDenyStillWins(t *testing.T) {
	// Deny still matches the static form, so a denied payload is cancelled
	// regardless of the appended-args handling.
	deny := patterns("Bash(rm:*)")
	result := Process(bash(`printf 'x\n' | xargs rm /tmp/safe`), nil, nil, deny, nil, nopLog())
	assert.Equal(t, ResultDenyRule, result.Kind)
}

func TestWrapperXargsClusteredOptionsDenyStillWins(t *testing.T) {
	// Clustered short options with a value-taking option (e.g. -0n 1, -S 999)
	// must not hide the payload: the deny on the real inner command still fires.
	deny := patterns("Bash(rm:*)")
	for _, cmd := range []string{
		`printf 'x\0' | xargs -0n 1 rm -rf`,
		`printf 'x\0' | xargs -0n1 rm -rf`,
		`printf 'x\n' | xargs -rn 1 rm -rf`,
		`printf 'x\n' | xargs -S 999 rm -rf`,
		`printf 'x\0' | xargs -0S 4096 rm -rf`,
	} {
		result := Process(bash(cmd), nil, nil, deny, nil, nopLog())
		assert.Equalf(t, ResultDenyRule, result.Kind, "cmd: %s (%s)", cmd, result.Reason)
	}
}

func TestWrapperDenyPayloadBeyondDepthLimitStillDenied(t *testing.T) {
	// Regression: a denied payload nested past maxWrapperDepth must still be
	// cancelled, not downgraded to an ask. The deny traversal is exhaustive, so
	// even wrappers stacked deeper than the approval path recurses cannot smuggle
	// a denied command through to a manual approval prompt.
	allow := patterns("Bash(grep:*)")
	deny := patterns("Bash(rm:*)")

	// maxWrapperDepth+2 layers of xargs wrapping a denied rm.
	denied := Process(bash(`echo f | xargs xargs xargs xargs xargs rm -rf`), allow, nil, deny, nil, nopLog())
	assert.Equal(t, ResultDenyRule, denied.Kind, "denied rm must be cancelled however deeply it is wrapped")

	// A safe payload nested equally deep is not denied — it simply can't be
	// auto-approved past the depth limit, so it defers (never silently allowed).
	deferred := Process(bash(`echo f | xargs xargs xargs xargs xargs grep -l foo`), allow, nil, deny, nil, nopLog())
	assert.Equal(t, ResultDefer, deferred.Kind, "an over-depth safe payload defers, not denied")
}

func TestWrapperDenyPayloadBeatsRedirect(t *testing.T) {
	// A denied payload must win even when a redirect would otherwise force an ask.
	allow := patterns("Bash(grep:*)")
	deny := patterns("Bash(rm:*)")
	result := Process(bash(`echo f | xargs rm -f 2>/etc/nope`), allow, nil, deny, nil, nopLog())
	assert.Equal(t, ResultDenyRule, result.Kind)
}

func TestWrapperFindExecAllowsSafePayload(t *testing.T) {
	allow := patterns("Bash(grep:*)", "Bash(cat:*)")
	tests := []string{
		`find . -name '*.go' -exec grep -l foo {} \;`,
		`find . -name '*.go' -exec grep X {} +`,
		`find . -type f -exec cat {} \;`,
	}
	for _, cmd := range tests {
		result := Process(bash(cmd), allow, nil, nil, nil, nopLog())
		assert.Equalf(t, ResultAllowed, result.Kind, "cmd: %s (%s)", cmd, result.Reason)
	}
}

func TestWrapperFindExecDefersDangerousPayload(t *testing.T) {
	allow := patterns("Bash(grep:*)", "Bash(find *)")
	// Even though `find *` is allow-listed, an -exec rm payload must not ride it:
	// the wrapper gate runs before the generic find allow, and rm isn't allowed,
	// so the hook defers.
	result := Process(bash(`find . -exec rm -rf {} \;`), allow, nil, nil, nil, nopLog())
	assert.Equal(t, ResultDefer, result.Kind)
}

func TestWrapperFindExecMixedPayloads(t *testing.T) {
	allow := patterns("Bash(grep:*)", "Bash(find *)")
	// First -exec is safe, second is not → overall defer.
	result := Process(bash(`find . -exec grep X {} \; -exec rm {} \;`), allow, nil, nil, nil, nopLog())
	assert.Equal(t, ResultDefer, result.Kind)
}

func TestWrapperFindExecMutatingActionDefers(t *testing.T) {
	// Regression: a safe -exec payload must not auto-approve a find that also
	// carries a side-effecting action. With only grep allowed and no ask rules,
	// these must not be approved — the hook defers so the destructive action
	// can't slip through on the strength of the -exec payload.
	allow := patterns("Bash(grep:*)")
	tests := []string{
		`find . -delete -exec grep X {} \;`,
		`find . -exec grep X {} \; -delete`,
		`find . -fprintf /tmp/out %p -exec grep X {} \;`,
		`find . -exec grep X {} \; -fls /tmp/list`,
		`find . -okdir grep X {} \; -exec grep Y {} \;`,
	}
	for _, cmd := range tests {
		result := Process(bash(cmd), allow, nil, nil, nil, nopLog())
		assert.Equalf(t, ResultDefer, result.Kind, "cmd: %s (%s)", cmd, result.Reason)
	}
}

func TestWrapperFindExecMutatingActionDenyStillWins(t *testing.T) {
	// A denied payload must still be cancelled even when the find also has a
	// mutating action that would otherwise force an ask.
	allow := patterns("Bash(grep:*)")
	deny := patterns("Bash(rm:*)")
	result := Process(bash(`find . -delete -exec rm {} \;`), allow, nil, deny, nil, nopLog())
	assert.Equal(t, ResultDenyRule, result.Kind)
}

func TestWrapperFindOkNotAllowedByGenericFind(t *testing.T) {
	// Regression: -ok/-okdir run a command but have no -exec, so they must not
	// ride a generic `Bash(find *)` allow — the hook defers instead.
	allow := patterns("Bash(find *)", "Bash(grep:*)")
	for _, cmd := range []string{
		`find . -ok rm {} \;`,
		`find . -okdir rm {} \;`,
	} {
		result := Process(bash(cmd), allow, nil, nil, nil, nopLog())
		assert.Equalf(t, ResultDefer, result.Kind, "cmd: %s (%s)", cmd, result.Reason)
	}
}

func TestWrapperFindExecLiteralPlusNotHidden(t *testing.T) {
	// Regression: a literal "+" argument must not truncate the payload and hide
	// later args from deny/ask checks.
	allow := patterns("Bash(grep:*)")
	deny := patterns("Bash(grep * /etc/shadow*)")
	// The /etc/shadow argument is now visible to the matcher, so the deny fires.
	denied := Process(bash(`find . -exec grep + /etc/shadow {} \;`), allow, nil, deny, nil, nopLog())
	assert.Equal(t, ResultDenyRule, denied.Kind)

	// The genuine batching terminator still allows a safe payload.
	ok := Process(bash(`find . -name "*.go" -exec grep -l foo {} +`), allow, nil, nil, nil, nopLog())
	assert.Equal(t, ResultAllowed, ok.Kind)
}

func TestWrapperFindExecPayloadActionTokenAllowed(t *testing.T) {
	// Regression: a mutating-looking token inside the -exec payload must not
	// force an ask — the find has no real mutating action and grep is allowed.
	allow := patterns("Bash(grep:*)")
	result := Process(bash(`find . -exec grep -e -delete {} \;`), allow, nil, nil, nil, nopLog())
	assert.Equalf(t, ResultAllowed, result.Kind, "reason: %s", result.Reason)
}

func TestWrapperPlainFindStillAllowed(t *testing.T) {
	allow := patterns("Bash(find *)")
	// find without -exec is not a wrapper; the generic allow applies.
	result := Process(bash(`find . -name '*.go' -type f`), allow, nil, nil, nil, nopLog())
	assert.Equal(t, ResultAllowed, result.Kind)
}

func TestWrapperFindExecAskRuleHonored(t *testing.T) {
	allow := patterns("Bash(grep:*)", "Bash(find *)")
	ask := patterns("Bash(find * -delete*)")
	// A -delete action elsewhere on the line must still trigger the ask rule,
	// even when an -exec payload would otherwise be safe.
	result := Process(bash(`find . -exec grep X {} \; -delete`), allow, ask, nil, nil, nopLog())
	assert.Equal(t, ResultAsk, result.Kind)
}

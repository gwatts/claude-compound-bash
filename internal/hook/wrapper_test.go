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

func TestWrapperXargsAsksDangerousPayload(t *testing.T) {
	allow := patterns("Bash(grep:*)", "Bash(rg:*)")
	// rm is not allow-listed, so the wrapper must defer to an ask.
	result := Process(bash(`rg --files | xargs rm -rf`), allow, nil, nil, nil, nopLog())
	assert.Equal(t, ResultAsk, result.Kind)
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

func TestWrapperFindExecAsksDangerousPayload(t *testing.T) {
	allow := patterns("Bash(grep:*)", "Bash(find *)")
	// Even though `find *` is allow-listed, an -exec rm payload must still ask:
	// the wrapper gate runs before the generic find allow.
	result := Process(bash(`find . -exec rm -rf {} \;`), allow, nil, nil, nil, nopLog())
	assert.Equal(t, ResultAsk, result.Kind)
}

func TestWrapperFindExecMixedPayloads(t *testing.T) {
	allow := patterns("Bash(grep:*)", "Bash(find *)")
	// First -exec is safe, second is not → overall ask.
	result := Process(bash(`find . -exec grep X {} \; -exec rm {} \;`), allow, nil, nil, nil, nopLog())
	assert.Equal(t, ResultAsk, result.Kind)
}

func TestWrapperFindExecMutatingActionAsks(t *testing.T) {
	// Regression: a safe -exec payload must not auto-approve a find that also
	// carries a side-effecting action. With only grep allowed and no ask rules,
	// these must still ask — the destructive action can't slip through.
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
		assert.Equalf(t, ResultAsk, result.Kind, "cmd: %s (%s)", cmd, result.Reason)
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
	// ride a generic `Bash(find *)` allow.
	allow := patterns("Bash(find *)", "Bash(grep:*)")
	for _, cmd := range []string{
		`find . -ok rm {} \;`,
		`find . -okdir rm {} \;`,
	} {
		result := Process(bash(cmd), allow, nil, nil, nil, nopLog())
		assert.Equalf(t, ResultAsk, result.Kind, "cmd: %s (%s)", cmd, result.Reason)
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

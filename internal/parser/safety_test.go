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
		{"ls", TierAlwaysInert},
		{"date", TierAlwaysInert},
		{"whoami", TierAlwaysInert},
		{"cat", TierAlwaysInert},
		{"wc", TierAlwaysInert},
		{"sleep", TierAlwaysInert},
		{"echo", TierSafeBuiltin},
		{"printf", TierSafeBuiltin},
		{"cd", TierSafeBuiltin},
		{"pwd", TierSafeBuiltin},
		{"exit", TierSafeBuiltin},
		{"return", TierSafeBuiltin},
		{"shift", TierSafeBuiltin},
		{"unset", TierSafeBuiltin},
		{"read", TierSafeBuiltin},
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

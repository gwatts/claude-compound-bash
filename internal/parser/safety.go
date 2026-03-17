package parser

// SafetyTier classifies how a builtin should be handled.
type SafetyTier int

const (
	// TierAlwaysInert — auto-allow unconditionally (read-only commands).
	TierAlwaysInert SafetyTier = iota
	// TierSafeBuiltin — shell builtins that are auto-allowed. Any commands
	// embedded in arguments via $(...) or <(...) are extracted by the AST
	// walker and checked separately.
	TierSafeBuiltin
	// TierNeverAllow — always require explicit pattern match.
	TierNeverAllow
	// TierNotBuiltin — not a recognized builtin, requires pattern match.
	TierNotBuiltin
)

// alwaysInert are read-only commands that cannot cause side effects
// regardless of arguments. Includes both shell builtins and common
// external commands that only read/display information.
var alwaysInert = map[string]bool{
	// Shell builtins
	"true":  true,
	"false": true,
	":":     true,
	"test":  true,
	"[":     true,
	"[[":    true,
	// Read-only external commands
	"ls":       true,
	"date":     true,
	"whoami":   true,
	"cat":      true,
	"head":     true,
	"tail":     true,
	"wc":       true,
	"uniq":     true,
	"basename": true,
	"dirname":  true,
	"realpath": true,
	"readlink": true,
	"which":    true,
	"file":     true,
	"stat":     true,
	"uname":    true,
	"id":       true,
	"hostname": true,
	"tr":       true,
	"cut":      true,
	"rev":      true,
	"seq":      true,
	"sleep":    true,
	"diff":     true,
	"comm":     true,
	"printenv": true,
}

// safeBuiltins are shell builtins that are auto-allowed. Any commands embedded
// in their arguments via $(...) or <(...) are extracted by the AST walker and
// checked as separate entries, so the builtin itself is always safe.
var safeBuiltins = map[string]bool{
	"echo":     true,
	"printf":   true,
	"cd":       true,
	"pwd":      true,
	"exit":     true,
	"return":   true,
	"shift":    true,
	"unset":    true,
	"read":     true,
	"pushd":    true,
	"popd":     true,
	"dirs":     true,
	"hash":     true,
	"type":     true,
	"umask":    true,
	"wait":     true,
	"times":    true,
	"ulimit":   true,
	"break":    true,
	"continue": true,
	"getopts":  true,
}

// neverAllow execute arbitrary code by design or mutate shell behavior
// in ways that affect subsequent command resolution.
var neverAllow = map[string]bool{
	"source":  true,
	".":       true,
	"eval":    true,
	"exec":    true,
	"set":     true,
	"trap":    true,
	"builtin": true, // "builtin eval x" runs eval directly; can't trust the second arg.
	"alias":   true, // alias can redirect command names to arbitrary strings.
	"unalias": true,
	"let":     true, // evaluates arithmetic expressions that can mutate variables.
}

// ClassifyBuiltin returns the safety tier for a command name.
func ClassifyBuiltin(name string) SafetyTier {
	if alwaysInert[name] {
		return TierAlwaysInert
	}
	if safeBuiltins[name] {
		return TierSafeBuiltin
	}
	if neverAllow[name] {
		return TierNeverAllow
	}
	return TierNotBuiltin
}

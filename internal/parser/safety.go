package parser

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// SafetyTier classifies how a builtin should be handled.
type SafetyTier int

const (
	// TierAlwaysInert — auto-allow unconditionally.
	TierAlwaysInert SafetyTier = iota
	// TierInertIfLiteral — auto-allow only if all args are literal (no CmdSubst/ProcSubst).
	TierInertIfLiteral
	// TierNeverAllow — always require explicit pattern match.
	TierNeverAllow
	// TierNotBuiltin — not a recognized builtin, requires pattern match.
	TierNotBuiltin
)

// alwaysInert cannot execute external code regardless of arguments.
var alwaysInert = map[string]bool{
	"true":  true,
	"false": true,
	":":     true,
	"test":  true,
	"[":     true,
	"[[":    true,
}

// inertIfLiteral are safe only when their arguments contain no command/process substitutions.
var inertIfLiteral = map[string]bool{
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
	if inertIfLiteral[name] {
		return TierInertIfLiteral
	}
	if neverAllow[name] {
		return TierNeverAllow
	}
	return TierNotBuiltin
}

// ArgsAreLiteral checks whether all argument words are free of command
// substitutions and process substitutions. This is the gate for tier-2 builtins.
func ArgsAreLiteral(command string) (bool, error) {
	r := strings.NewReader(command)
	parser := syntax.NewParser(syntax.KeepComments(false))
	file, err := parser.Parse(r, "")
	if err != nil {
		return false, err
	}

	if len(file.Stmts) == 0 {
		return true, nil
	}

	stmt := file.Stmts[0]
	if call, ok := stmt.Cmd.(*syntax.CallExpr); ok {
		if len(call.Args) > 1 {
			if !wordsAreLiteral(call.Args[1:]) {
				return false, nil
			}
		}
	}
	if decl, ok := stmt.Cmd.(*syntax.DeclClause); ok {
		for _, assign := range decl.Args {
			if assign.Value != nil && !wordIsLiteral(assign.Value) {
				return false, nil
			}
		}
	}
	return true, nil
}

// ArgsAreLiteralWords checks whether the given words (from a parsed AST) are
// free of command substitutions and process substitutions.
func ArgsAreLiteralWords(args []*syntax.Word) bool {
	return wordsAreLiteral(args)
}

func wordsAreLiteral(words []*syntax.Word) bool {
	for _, w := range words {
		if !wordIsLiteral(w) {
			return false
		}
	}
	return true
}

func wordIsLiteral(w *syntax.Word) bool {
	for _, part := range w.Parts {
		if !partIsLiteral(part) {
			return false
		}
	}
	return true
}

func partIsLiteral(part syntax.WordPart) bool {
	switch p := part.(type) {
	case *syntax.Lit:
		return true
	case *syntax.SglQuoted:
		return true
	case *syntax.DblQuoted:
		for _, inner := range p.Parts {
			if !partIsLiteral(inner) {
				return false
			}
		}
		return true
	case *syntax.ParamExp:
		// $VAR is fine in arguments — variable expansion doesn't execute commands.
		// But check if there's a command substitution in the default/alternative value.
		if p.Exp != nil && p.Exp.Word != nil {
			if !wordIsLiteral(p.Exp.Word) {
				return false
			}
		}
		return true
	case *syntax.CmdSubst:
		return false
	case *syntax.ProcSubst:
		return false
	case *syntax.ArithmExp:
		// Arithmetic is safe — no command execution.
		return true
	case *syntax.ExtGlob:
		return true
	case *syntax.BraceExp:
		return true
	default:
		// Unknown part type — be conservative.
		return false
	}
}

package parser

import (
	"os"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// intrinsicVarNames are process-environment variables whose value is safe to
// substitute into a redirect target when the command itself never assigns or
// unsets them. They let a target the model writes symbolically resolve to the
// literal path a user's trusted-directory list holds:
//   - HOME: an allow entry like /Users/joe/logs is matched by a redirect the
//     model writes as "$HOME/logs/app.log" (allow lists take literal absolute
//     paths, so the two only meet once the variable is resolved).
//   - TMPDIR: the standard system temp location, pairing with the /tmp special
//     case in ExpandAdditionalDirs so "$TMPDIR/x" completes a path the allow
//     list already trusts when /tmp is permitted.
var intrinsicVarNames = []string{"HOME", "TMPDIR"}

// intrinsicVars reads the intrinsic variables from the process environment,
// which the Bash tool inherits, so their value matches what the command will
// see — provided the command doesn't reassign them (see collectAssignedNames).
// Names that are unset or empty are omitted; values are cleaned so a trailing
// slash (as macOS gives TMPDIR) doesn't leak into the resolved path.
func intrinsicVars() map[string]string {
	var m map[string]string
	for _, name := range intrinsicVarNames {
		v := os.Getenv(name)
		if v == "" {
			continue
		}
		if m == nil {
			m = make(map[string]string, len(intrinsicVarNames))
		}
		m[name] = filepath.Clean(v)
	}
	return m
}

// unboundedScope marks an assignment that persists in the current shell for the
// rest of the command (i.e. every later offset is within its scope).
const unboundedScope = ^uint(0)

// literalAssign is a `NAME=value` assignment whose value is fully static,
// recorded in source order so a later redirect can resolve a variable reference
// to the exact path bash would use at that point in the command. scopeEnd bounds
// where the value applies: a top-level assignment persists to the end of the
// command (unboundedScope), while one inside a backgrounded unit or a subshell
// applies only to redirects within that same unit (its value never reaches the
// current shell afterward).
type literalAssign struct {
	offset   uint // byte offset of the assignment in the source
	scopeEnd uint // exclusive upper bound of offsets this value applies to
	name     string
	value    string
}

// collectLiteralAssigns finds the static `NAME=value` assignments a later
// redirect can safely resolve against: those guaranteed to run before the
// redirect is reached, each tagged with the scope its value survives in.
//
// It scans the top-level statement list — each entry runs unconditionally in
// sequence — and within each entry follows `&&`/`||` chains: an `&&`-only chain
// runs its operands in order, so `cd d && SCRATCH=/dir && cmd > "$SCRATCH/f"`
// resolves, while a chain mixing in `||` falls back to the always-run left
// spine. It also descends into subshells and backgrounded units, but tags those
// assignments with the unit's extent so they resolve only redirects inside the
// same unit (matching bash: the value never escapes to the current shell).
// Assignments that may not run are ignored: a command-prefix assignment
// (`FOO=bar cmd` — bash expands the redirect before applying it), and anything
// inside a loop, if/case body, or function body.
func collectLiteralAssigns(file *syntax.File) []literalAssign {
	var out []literalAssign
	for _, stmt := range file.Stmts {
		collectLeadingAssigns(stmt, unboundedScope, &out)
	}
	return out
}

// collectLeadingAssigns appends the static assignments in stmt that a later
// redirect can resolve against, each recorded with scopeEnd — the exclusive
// offset past which its value no longer applies. A bare assignment statement
// qualifies directly. For an `&&`-only chain every operand runs in sequence, so
// an assignment resolves any redirect further down that same chain (scoped to
// the chain when a fallible command precedes it, since its value may not survive
// to a later statement). For a chain that mixes in `||`, only the sound subset
// is taken: the left operand always runs first, and — past a run of pure,
// always-succeeding assignments joined by `&&` — so do the right operands. A
// backgrounded unit or subshell narrows scopeEnd to that unit's extent, since
// its assignments don't reach the current shell.
func collectLeadingAssigns(stmt *syntax.Stmt, scopeEnd uint, out *[]literalAssign) {
	if stmt.Coprocess {
		return
	}
	// A backgrounded statement runs in a subshell: its assignments apply only
	// within this statement, never to the current shell afterward.
	if stmt.Background {
		if e := stmt.End().Offset(); e < scopeEnd {
			scopeEnd = e
		}
	}
	switch cmd := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		// A command prefix (args present) doesn't persist past the command,
		// and its value isn't in effect for that command's own redirects.
		if len(cmd.Args) != 0 {
			return
		}
		for _, a := range cmd.Assigns {
			if name, value, ok := staticAssign(a); ok {
				*out = append(*out, literalAssign{offset: a.Pos().Offset(), scopeEnd: scopeEnd, name: name, value: value})
			}
		}
	case *syntax.BinaryCmd:
		if cmd.Op != syntax.AndStmt && cmd.Op != syntax.OrStmt {
			return
		}
		// An `&&`-only chain (no `||` in its spine) executes strictly left to
		// right, each operand only if every earlier one succeeded. That lets an
		// assignment gated behind a command — `cd d && S=/dir && cmd > "$S/f"` —
		// resolve a redirect further down the same chain: reaching that redirect
		// implies the assignment ran. collectAndChainOps scopes such gated
		// assignments to the chain so they never leak to a later statement.
		if cmd.Op == syntax.AndStmt {
			if ops, ok := andChainOperands(cmd); ok {
				collectAndChainOps(stmt.End().Offset(), ops, scopeEnd, out)
				return
			}
		}
		// A `||`, or a mix of `&&`/`||`, doesn't give that guarantee. Fall back
		// to the sound subset: the left operand always executes first, and — past
		// a run of pure, always-succeeding assignments joined by `&&` — so does
		// the right (after `||` a succeeding left skips the right).
		collectLeadingAssigns(cmd.X, scopeEnd, out)
		if cmd.Op == syntax.AndStmt && isPureAssignChain(cmd.X) {
			collectLeadingAssigns(cmd.Y, scopeEnd, out)
		}
	case *syntax.Subshell:
		// A subshell's assignments apply only within it. Its statements run in
		// sequence, so each is a leading assignment within the narrowed scope.
		if e := stmt.End().Offset(); e < scopeEnd {
			scopeEnd = e
		}
		for _, s := range cmd.Stmts {
			collectLeadingAssigns(s, scopeEnd, out)
		}
	}
}

// isPureAssignChain reports whether stmt is a static assignment, or an
// `&&`/`||` chain built only from such assignments. Such a statement always
// exits 0 and runs no external command, so a following `&&` operand is
// guaranteed to run. A dynamic value (e.g. `A=$(cmd)`) disqualifies it: it can
// set a non-zero status and isn't a value we track anyway.
func isPureAssignChain(stmt *syntax.Stmt) bool {
	if stmt.Negated || stmt.Background || stmt.Coprocess {
		return false
	}
	switch cmd := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		if len(cmd.Args) != 0 || len(cmd.Assigns) == 0 {
			return false
		}
		for _, a := range cmd.Assigns {
			if _, _, ok := staticAssign(a); !ok {
				return false
			}
		}
		return true
	case *syntax.BinaryCmd:
		if cmd.Op != syntax.AndStmt && cmd.Op != syntax.OrStmt {
			return false
		}
		return isPureAssignChain(cmd.X) && isPureAssignChain(cmd.Y)
	}
	return false
}

// andChainOperands flattens an `&&`-only BinaryCmd into its operand statements
// in execution order. It returns ok=false if the chain's spine contains any
// `||` (OrStmt): after a `||`, reaching a later operand no longer implies an
// earlier assignment ran, so the chain can't be treated as a guaranteed
// left-to-right sequence. A `||` nested inside a subshell operand — `(a || b) &&
// cmd` — is opaque and doesn't disqualify the chain.
func andChainOperands(cmd *syntax.BinaryCmd) ([]*syntax.Stmt, bool) {
	left, ok := operandChain(cmd.X)
	if !ok {
		return nil, false
	}
	right, ok := operandChain(cmd.Y)
	if !ok {
		return nil, false
	}
	return append(left, right...), true
}

// operandChain returns stmt's operands: a further `&&`-only chain flattens into
// its operands, anything else is a single opaque operand. A backgrounded,
// negated, or coprocess operand, or one whose command isn't a bare `&&`/`||`
// BinaryCmd (a pipe, subshell, call, etc.), is returned as one operand and left
// for the normal per-operand descent to handle. A spine `||` returns ok=false.
func operandChain(stmt *syntax.Stmt) ([]*syntax.Stmt, bool) {
	if stmt.Background || stmt.Negated || stmt.Coprocess {
		return []*syntax.Stmt{stmt}, true
	}
	bc, ok := stmt.Cmd.(*syntax.BinaryCmd)
	if !ok || (bc.Op != syntax.AndStmt && bc.Op != syntax.OrStmt) {
		return []*syntax.Stmt{stmt}, true
	}
	if bc.Op == syntax.OrStmt {
		return nil, false
	}
	return andChainOperands(bc)
}

// collectAndChainOps collects the static assignments in the operands of an
// `&&`-only chain (in execution order), choosing each operand's scope by whether
// it is guaranteed to run in the current shell. While every earlier operand is a
// pure, always-succeeding assignment chain, an operand is guaranteed to run and
// its value reaches the current shell, so it keeps the inherited scopeEnd (a
// top-level `S=/a && cmd` still resolves "$S" in a later statement). Once a
// fallible command has intervened, an operand runs only when that command
// succeeded: its assignments still hold for redirects further down this same
// chain, but not for any later statement, so they are scoped to chainEnd.
func collectAndChainOps(chainEnd uint, ops []*syntax.Stmt, scopeEnd uint, out *[]literalAssign) {
	gatedEnd := min(scopeEnd, chainEnd)
	guaranteed := true
	for _, op := range ops {
		opScope := scopeEnd
		if !guaranteed {
			opScope = gatedEnd
		}
		collectLeadingAssigns(op, opScope, out)
		if !isPureAssignChain(op) {
			guaranteed = false
		}
	}
}

// resolvableVars determines which variables a redirect target may safely be
// resolved against, given the whole command.
//
// It starts from the guaranteed-leading static assignments and the intrinsic
// environment variables, then removes every variable whose value at the
// redirect can't be trusted: one that is also assigned or unset somewhere we
// don't account for — a conditional or nested reassignment, an export/declare,
// a dynamic value, an unset, or a command prefix. Such a variable might hold a
// different value at run time than any assignment we captured, so it must stay
// dynamic rather than resolve to a stale value.
func resolvableVars(file *syntax.File) (assigns []literalAssign, intrinsics map[string]string) {
	assigns = collectLiteralAssigns(file)
	intrinsics = intrinsicVars()
	if len(assigns) == 0 && len(intrinsics) == 0 {
		return nil, nil
	}

	// Offsets of the assignments we treat as guaranteed-leading and static.
	safe := make(map[uint]bool, len(assigns))
	for _, a := range assigns {
		safe[a.offset] = true
	}

	// Names touched by any assignment or unset that isn't one of those.
	uncertain := make(map[string]bool)
	syntax.Walk(file, func(node syntax.Node) bool {
		switch x := node.(type) {
		case *syntax.Assign:
			if x.Name != nil && !safe[x.Pos().Offset()] {
				uncertain[x.Name.Value] = true
			}
		case *syntax.CallExpr:
			for _, name := range unsetTargets(x) {
				uncertain[name] = true
			}
		}
		return true
	})

	if len(uncertain) == 0 {
		return assigns, intrinsics
	}
	for name := range intrinsics {
		if uncertain[name] {
			delete(intrinsics, name)
		}
	}
	kept := assigns[:0]
	for _, a := range assigns {
		if !uncertain[a.name] {
			kept = append(kept, a)
		}
	}
	return kept, intrinsics
}

// unsetTargets returns the variable names an `unset VAR ...` command clears in
// the current shell. It returns nil for any other command. Flags (-v, -f) and
// dynamic operands are skipped.
func unsetTargets(call *syntax.CallExpr) []string {
	if len(call.Args) == 0 {
		return nil
	}
	if name, ok := staticWordValue(call.Args[0]); !ok || name != "unset" {
		return nil
	}
	var names []string
	for _, arg := range call.Args[1:] {
		name, ok := staticWordValue(arg)
		if !ok || strings.HasPrefix(name, "-") {
			continue
		}
		names = append(names, name)
	}
	return names
}

// staticAssign returns the name and fully-static value of a simple scalar
// assignment (`NAME=value`). It returns ok=false for array assignments
// (`NAME=(...)`), appends (`NAME+=value`), indexed assignments (`NAME[i]=`),
// naked declarations (`declare NAME`), or any value that isn't fully static.
func staticAssign(a *syntax.Assign) (name, value string, ok bool) {
	if a.Naked || a.Append || a.Index != nil || a.Array != nil || a.Name == nil || a.Value == nil {
		return "", "", false
	}
	value, ok = staticWordValue(a.Value)
	if !ok {
		return "", "", false
	}
	return a.Name.Value, value, true
}

// staticWordValue returns the literal value of an assignment RHS, or ok=false
// if it contains any expansion. A tilde anywhere is rejected because bash
// performs tilde expansion in assignment context, so the source text would not
// be the runtime value. (Variable chaining like `A=$B/x` is intentionally not
// resolved here; such a value stays unknown and its uses remain dynamic.)
func staticWordValue(w *syntax.Word) (string, bool) {
	var sb strings.Builder
	if !appendLiteralParts(&sb, w.Parts) {
		return "", false
	}
	v := sb.String()
	if strings.Contains(v, "~") {
		return "", false
	}
	return v, true
}

// appendLiteralParts writes the literal content of word parts to sb, returning
// false if any part is an expansion rather than plain or quoted text.
func appendLiteralParts(sb *strings.Builder, parts []syntax.WordPart) bool {
	for _, part := range parts {
		switch p := part.(type) {
		case *syntax.Lit:
			sb.WriteString(p.Value)
		case *syntax.SglQuoted:
			if p.Dollar {
				return false // $'...' processes escapes; not a plain literal
			}
			sb.WriteString(p.Value)
		case *syntax.DblQuoted:
			if !appendLiteralParts(sb, p.Parts) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// expandRedirectTarget resolves a redirect target word to a literal path using
// the given variables. It returns ok=false when the word contains any expansion
// that isn't a plain reference to a known variable, or when the substituted
// result would still be subject to bash tilde or glob expansion.
func expandRedirectTarget(w *syntax.Word, vars map[string]string) (string, bool) {
	if len(vars) == 0 {
		return "", false // nothing to resolve against
	}
	var sb strings.Builder
	if !appendExpandedParts(&sb, w.Parts, vars) {
		return "", false
	}
	v := sb.String()
	// The substituted result must be a plain path. Reject tilde and glob
	// metacharacters exactly as isLiteralRedirectTarget does for source
	// literals, so a resolved target is never treated more leniently than one
	// written out in full.
	if strings.HasPrefix(v, "~") || strings.ContainsAny(v, "*?[") ||
		strings.Contains(v, "@(") || strings.Contains(v, "+(") ||
		strings.Contains(v, "!(") || strings.Contains(v, "*(") {
		return "", false
	}
	return v, true
}

// appendExpandedParts writes word parts to sb, substituting plain variable
// references from vars. It returns false on any expansion that isn't a plain
// reference to a known variable.
func appendExpandedParts(sb *strings.Builder, parts []syntax.WordPart, vars map[string]string) bool {
	for _, part := range parts {
		switch p := part.(type) {
		case *syntax.Lit:
			sb.WriteString(p.Value)
		case *syntax.SglQuoted:
			if p.Dollar {
				return false
			}
			sb.WriteString(p.Value)
		case *syntax.DblQuoted:
			if !appendExpandedParts(sb, p.Parts, vars) {
				return false
			}
		case *syntax.ParamExp:
			v, ok := simpleParamValue(p, vars)
			if !ok {
				return false
			}
			sb.WriteString(v)
		default:
			return false
		}
	}
	return true
}

// simpleParamValue returns the value of a plain `$name`/`${name}` reference
// from vars. Any modifier (${!x}, ${#x}, ${x:-y}, ${x[i]}, slices, replacement,
// zsh flags, nesting, etc.) makes the expansion non-trivial and yields
// ok=false, as does a name that has no known static value.
func simpleParamValue(pe *syntax.ParamExp, vars map[string]string) (string, bool) {
	if pe.Excl || pe.Length || pe.Width || pe.IsSet || pe.Flags != nil ||
		pe.NestedParam != nil || pe.Index != nil || len(pe.Modifiers) > 0 ||
		pe.Slice != nil || pe.Repl != nil || pe.Names != 0 || pe.Exp != nil {
		return "", false
	}
	if pe.Param == nil {
		return "", false
	}
	v, ok := vars[pe.Param.Value]
	return v, ok
}

// effectiveVars returns the variables in scope for a redirect at offset:
// intrinsic environment variables as the base, overlaid with the command's own
// static assignments that apply at that offset — those that run before it
// (a.offset < offset) and whose scope still covers it (offset < a.scopeEnd), so
// a subshell/background assignment resolves a redirect inside the same unit but
// not one after it. An in-command assignment always wins over the inherited
// value. assigns is in source order, so the last applicable one to each name
// wins.
func effectiveVars(assigns []literalAssign, intrinsics map[string]string, offset uint) map[string]string {
	var vars map[string]string
	if len(intrinsics) > 0 {
		vars = make(map[string]string, len(intrinsics)+len(assigns))
		for k, v := range intrinsics {
			vars[k] = v
		}
	}
	for _, a := range assigns {
		if a.offset >= offset || offset >= a.scopeEnd {
			continue
		}
		if vars == nil {
			vars = make(map[string]string)
		}
		vars[a.name] = a.value
	}
	return vars
}

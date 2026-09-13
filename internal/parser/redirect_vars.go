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

// literalAssign is a top-level `NAME=value` assignment whose value is fully
// static, recorded in source order so a later redirect can resolve a variable
// reference to the exact path bash would use at that point in the command.
type literalAssign struct {
	offset uint // byte offset of the assignment statement in the source
	name   string
	value  string
}

// collectLiteralAssigns scans the top-level statement list for standalone,
// unconditional `NAME=value` assignments whose value is fully static (no
// expansions, no tilde).
//
// Only direct children of the file's statement list qualify. Assignments
// inside a subshell, brace group, loop, if/case body, function body, or a
// `&&`/`||` branch are ignored because they may not run — or their value may
// not survive — at the point a later redirect is expanded. A command-prefix
// assignment (`FOO=bar cmd`) is ignored too: bash expands a redirect target
// before applying the prefix, so the prefix value isn't in effect for that
// command's own redirects. Both cases are excluded by the same rule — the
// statement's command must be a bare CallExpr with assignments and no args.
func collectLiteralAssigns(file *syntax.File) []literalAssign {
	var out []literalAssign
	for _, stmt := range file.Stmts {
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) != 0 || len(call.Assigns) == 0 {
			continue
		}
		// Negation (`! FOO=bar`) and backgrounding (`FOO=bar &`) don't change
		// the assigned value, so they need no special handling here.
		for _, a := range call.Assigns {
			name, value, ok := staticAssign(a)
			if !ok {
				continue
			}
			out = append(out, literalAssign{offset: stmt.Pos().Offset(), name: name, value: value})
		}
	}
	return out
}

// collectAssignedNames returns the set of variable names the command assigns or
// unsets anywhere — including command prefixes, exports/declares, and function
// bodies (which run in the current shell). A name in this set can't be resolved
// from the inherited environment, because the command may change its value
// before the redirect is expanded, so intrinsic expansion skips it.
func collectAssignedNames(file *syntax.File) map[string]bool {
	names := make(map[string]bool)
	syntax.Walk(file, func(node syntax.Node) bool {
		switch x := node.(type) {
		case *syntax.Assign:
			if x.Name != nil {
				names[x.Name.Value] = true
			}
		case *syntax.CallExpr:
			// `unset VAR ...` clears variables in the current shell.
			if len(x.Args) == 0 {
				return true
			}
			if name, ok := staticWordValue(x.Args[0]); !ok || name != "unset" {
				return true
			}
			for _, arg := range x.Args[1:] {
				name, ok := staticWordValue(arg)
				if !ok || strings.HasPrefix(name, "-") {
					continue // skip flags (-v, -f) and dynamic names
				}
				names[name] = true
			}
		}
		return true
	})
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
// static assignments that take effect before offset (an in-command assignment
// always wins over the inherited value). assigns is in source order, so the
// scan stops at the first assignment at or after offset.
func effectiveVars(assigns []literalAssign, intrinsics map[string]string, offset uint) map[string]string {
	var vars map[string]string
	if len(intrinsics) > 0 {
		vars = make(map[string]string, len(intrinsics)+len(assigns))
		for k, v := range intrinsics {
			vars[k] = v
		}
	}
	for _, a := range assigns {
		if a.offset >= offset {
			break
		}
		if vars == nil {
			vars = make(map[string]string)
		}
		vars[a.name] = a.value
	}
	return vars
}

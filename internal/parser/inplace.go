package parser

import (
	"path/filepath"
	"runtime"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// WriteTarget is a file path that a command modifies, together with whether the
// path is a static literal (no variables, globs, tilde, or command substitution).
// A non-literal target cannot be resolved at hook time and is treated as unsafe.
type WriteTarget struct {
	// Raw is the target's original source text (for logs and reasons).
	Raw string
	// Path is the unquoted literal path when Literal is true; otherwise the raw
	// source text (which cannot be resolved).
	Path string
	// Literal is true when Path is a fully static path safe to resolve.
	Literal bool
}

// toolSpec describes how to find the in-place file operands of one editor.
type toolSpec struct {
	// argShort are short option letters that consume an argument (attached in the
	// same token, e.g. -e's/a/b/', or as the following token, e.g. -e 's/a/b/').
	argShort string
	// scriptShort are the arg-consuming short options that supply the program, so
	// no operand is treated as the script (sed -e/-f, perl -e/-E, awk -e/-f).
	scriptShort string
	// inPlaceShort enables in-place mode when present (sed/perl -i, awk -i).
	inPlaceShort byte
	// inPlaceNeedsValue requires inPlaceShort's argument to equal inPlaceValue for
	// in-place mode (awk: -i inplace).
	inPlaceNeedsValue bool
	inPlaceValue      string
	// longArg are long options that consume the following token when not given as
	// --opt=value.
	longArg map[string]bool
	// inPlaceLong enables in-place mode (sed --in-place).
	inPlaceLong map[string]bool
	// scriptLong suppress the operand-script (sed --expression/--file).
	scriptLong map[string]bool
	// skipScriptOperand: when no script option was seen, the first operand is the
	// program text and is not a file (sed, perl, awk).
	skipScriptOperand bool
	// skipAssignOperands: drop var=val operands, which are awk assignments, not
	// files.
	skipAssignOperands bool
}

// bsdSed selects BSD sed option parsing over GNU. It follows the platform's
// default sed and is a variable so tests can exercise both dialects.
var bsdSed = runtime.GOOS == "darwin"

// sedArgShort differs by dialect: BSD sed (-i takes a mandatory suffix
// argument) vs GNU sed (-i's suffix is attached only, never a separate token).
func sedArgShort() string {
	if bsdSed {
		return "efi"
	}
	return "ef"
}

func specForTool(name string) (toolSpec, bool) {
	switch filepath.Base(name) {
	case "sed", "gsed":
		return toolSpec{
			argShort:          sedArgShort(),
			scriptShort:       "ef",
			inPlaceShort:      'i',
			longArg:           map[string]bool{"expression": true, "file": true},
			inPlaceLong:       map[string]bool{"in-place": true},
			scriptLong:        map[string]bool{"expression": true, "file": true},
			skipScriptOperand: true,
		}, true
	case "perl":
		return toolSpec{
			argShort:          "eEMmI",
			scriptShort:       "eE",
			inPlaceShort:      'i',
			skipScriptOperand: true,
		}, true
	case "awk", "gawk", "mawk":
		return toolSpec{
			argShort:           "vFfeil",
			scriptShort:        "fe",
			inPlaceShort:       'i',
			inPlaceNeedsValue:  true,
			inPlaceValue:       "inplace",
			skipScriptOperand:  true,
			skipAssignOperands: true,
		}, true
	}
	return toolSpec{}, false
}

// inPlaceTargets returns the files an in-place editing command rewrites, or nil
// if name is not an in-place editor or no -i/in-place flag is present. args must
// include the command name as args[0] (as syntax.CallExpr.Args does).
func inPlaceTargets(name string, args []*syntax.Word) []WriteTarget {
	spec, ok := specForTool(name)
	if !ok || len(args) < 2 {
		return nil
	}

	var operands []WriteTarget
	scriptSuppressed := false
	inPlace := false
	endOpts := false

	for i := 1; i < len(args); i++ {
		val, literal := literalValue(args[i])

		if !endOpts && literal && val == "--" {
			endOpts = true
			continue
		}

		if !endOpts && literal && strings.HasPrefix(val, "-") && val != "-" {
			if strings.HasPrefix(val, "--") {
				name := strings.TrimPrefix(val, "--")
				bare, hasEq := name, false
				if eq := strings.IndexByte(name, '='); eq >= 0 {
					bare, hasEq = name[:eq], true
				}
				if spec.inPlaceLong[bare] {
					inPlace = true
				}
				if spec.scriptLong[bare] {
					scriptSuppressed = true
				}
				if !hasEq && spec.longArg[bare] {
					i++ // consumes the following token as its argument
				}
				continue
			}
			consumeInPlaceCluster(spec, val[1:], args, &i, &inPlace, &scriptSuppressed)
			continue
		}

		// Operand: an in-place target candidate (or the script / an assignment).
		operands = append(operands, WriteTarget{
			Raw:     rawWord(args[i]),
			Path:    val,
			Literal: literal && isLiteralRedirectTarget(args[i]),
		})
	}

	if !inPlace {
		return nil
	}

	files := operands
	if spec.skipScriptOperand && !scriptSuppressed && len(files) > 0 {
		files = files[1:] // the first operand is the program text, not a file
	}
	if spec.skipAssignOperands {
		files = filterAssignments(files)
	}
	if len(files) == 0 {
		return nil
	}
	return files
}

// consumeInPlaceCluster parses one short-option cluster (the token after the
// leading '-'), updating inPlace / scriptSuppressed and advancing *i past any
// following token consumed as an option argument.
func consumeInPlaceCluster(spec toolSpec, cluster string, args []*syntax.Word, i *int, inPlace, scriptSuppressed *bool) {
	for j := 0; j < len(cluster); j++ {
		c := cluster[j]
		if spec.inPlaceShort != 0 && c == spec.inPlaceShort && !spec.inPlaceNeedsValue {
			*inPlace = true
		}
		if !strings.ContainsRune(spec.argShort, rune(c)) {
			continue
		}
		// c consumes an argument: the rest of the cluster if non-empty, else the
		// following token.
		argVal, argLit := cluster[j+1:], true
		if len(cluster) == j+1 {
			if *i+1 < len(args) {
				*i++
				argVal, argLit = literalValue(args[*i])
			} else {
				argVal, argLit = "", false
			}
		}
		if c == spec.inPlaceShort && spec.inPlaceNeedsValue && argLit && argVal == spec.inPlaceValue {
			*inPlace = true
		}
		if strings.ContainsRune(spec.scriptShort, rune(c)) {
			*scriptSuppressed = true
		}
		return // rest of the cluster was this option's argument
	}
}

// filterAssignments drops literal var=val operands (awk assignments).
func filterAssignments(in []WriteTarget) []WriteTarget {
	out := in[:0:0]
	for _, t := range in {
		if t.Literal && isAssignmentOperand(t.Path) {
			continue
		}
		out = append(out, t)
	}
	return out
}

// isAssignmentOperand reports whether s is an awk name=value assignment operand.
func isAssignmentOperand(s string) bool {
	eq := strings.IndexByte(s, '=')
	if eq <= 0 {
		return false
	}
	for i, r := range s[:eq] {
		if r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			continue
		}
		if i > 0 && r >= '0' && r <= '9' {
			continue
		}
		return false
	}
	return true
}

// literalValue returns the unquoted static value of a word and whether the word
// is fully literal (only Lit / single- or double-quoted literal parts, no
// expansions). The value is meaningful only when the bool is true.
func literalValue(w *syntax.Word) (string, bool) {
	if !isLiteralWord(w) {
		return "", false
	}
	var sb strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			sb.WriteString(p.Value)
		case *syntax.SglQuoted:
			sb.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, inner := range p.Parts {
				if lit, ok := inner.(*syntax.Lit); ok {
					sb.WriteString(lit.Value)
				}
			}
		}
	}
	return sb.String(), true
}

// rawWord returns a word's source text for logs and reasons.
func rawWord(w *syntax.Word) string {
	printer := syntax.NewPrinter()
	return printNode(printer, w)
}

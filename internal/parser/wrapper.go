package parser

import "strings"

// WrapperInner inspects a command and, if it is a recognized command wrapper,
// returns the inner command(s) that the wrapper will execute on its behalf.
//
// A wrapper is a command whose own name reveals nothing about what actually
// runs — the danger (or safety) lives in the payload it forwards:
//
//   - xargs [opts] CMD ...                runs CMD with stdin-derived args
//   - find ... -exec CMD ... {} ;|+       runs CMD for each match
//   - find ... -execdir CMD ... {} ;|+    same, in each match's directory
//
// isWrapper is true whenever cmd is one of these recognized forms that must be
// gated on its payload rather than auto-allowed by its own name. When isWrapper
// is true but the payload can't be determined (e.g. malformed xargs options, or
// an -exec with no command), inners is empty and the caller must fail closed by
// asking — never allow a wrapper whose payload we couldn't read.
//
// Plain find with no -exec/-execdir is NOT a wrapper: it's a read-only search
// handled by the caller's normal rules, so isWrapper is false for it.
func WrapperInner(cmd Command) (inners []Command, isWrapper bool) {
	if cmd.Dynamic || len(cmd.Args) == 0 {
		return nil, false
	}

	switch cmd.Name {
	case "xargs":
		if inner, ok := xargsInner(cmd.Args); ok {
			return []Command{inner}, true
		}
		return nil, true // recognized wrapper, payload undeterminable → caller asks
	case "find":
		if !findHasExec(cmd.Args) {
			if findHasMutatingAction(cmd.Args) {
				// A mutating action (-delete, -ok, ...) with no -exec payload to
				// validate must not ride the generic `find *` allow → fail closed.
				return nil, true
			}
			return nil, false // plain search — defer to normal rules
		}
		return findExecInners(cmd.Args), true
	}

	return nil, false
}

// xargsShortOptsWithArg are the single-letter xargs options that consume a
// following separate argument (e.g. "-n 1", "-I {}"). Covers the union of BSD
// (macOS) and GNU xargs. Options with an attached value ("-n1", "-I{}") need no
// special handling — they are a single token and skipped as one.
var xargsShortOptsWithArg = map[byte]bool{
	'I': true, 'J': true, 'L': true, 'n': true,
	'P': true, 's': true, 'E': true, 'a': true,
	'd': true, 'R': true,
}

// xargsLongOptsWithArg are the GNU long options that consume a following
// separate argument when written without "=".
var xargsLongOptsWithArg = map[string]bool{
	"--max-args": true, "--max-procs": true, "--max-lines": true,
	"--replace": true, "--delimiter": true, "--eof": true,
	"--arg-file": true, "--max-chars": true, "--process-slot-var": true,
}

// xargsInner skips xargs's own options and returns the wrapped command. ok is
// false when no command word can be identified (only options, or an option
// swallowed what would have been the command — both fail closed to an ask).
func xargsInner(args []string) (Command, bool) {
	i := 1 // args[0] == "xargs"
	for i < len(args) {
		a := args[i]
		switch {
		case a == "--":
			i++
			if i < len(args) {
				return commandFromArgs(args[i:]), true
			}
			return Command{}, false
		case strings.HasPrefix(a, "--"):
			// A long option consumes the next token only when it takes a value
			// and that value isn't already attached via "=".
			if !strings.ContainsRune(a, '=') && xargsLongOptsWithArg[a] {
				i++
			}
			i++
		case len(a) > 1 && a[0] == '-':
			// Short option(s). A separate argument is consumed only when the
			// option is written bare (e.g. "-n 1"); attached forms ("-n1",
			// "-I{}") and boolean clusters ("-0", "-rt") are one token.
			if len(a) == 2 && xargsShortOptsWithArg[a[1]] {
				i++ // skip the option's separate argument
			}
			i++
		default:
			return commandFromArgs(args[i:]), true
		}
	}
	return Command{}, false
}

// findHasExec reports whether a find argument list contains an -exec/-execdir
// action, whose payload runs an arbitrary command.
func findHasExec(args []string) bool {
	for _, a := range args {
		if a == "-exec" || a == "-execdir" {
			return true
		}
	}
	return false
}

// findMutatingActions are find primaries that cause side effects -- deleting or
// writing files, or running a command we do not extract as a payload. They are
// distinct from -exec/-execdir, whose command we validate separately. -ok and
// -okdir run commands too, but their payload is never auto-approved (and their
// interactive prompt can't be answered from a hook), so they belong here.
var findMutatingActions = map[string]bool{
	"-delete":  true,
	"-ok":      true,
	"-okdir":   true,
	"-fprint":  true,
	"-fprint0": true,
	"-fprintf": true,
	"-fls":     true,
}

// FindHasMutatingNonExecAction reports whether cmd is a find command whose
// expression contains a side-effecting action other than -exec/-execdir. Such a
// find must not be auto-approved on the strength of a safe -exec payload alone:
// `find . -delete -exec grep X {} \;` deletes files regardless of how benign the
// -exec is. Returns false for any command that is not find.
func FindHasMutatingNonExecAction(cmd Command) bool {
	return cmd.Name == "find" && findHasMutatingAction(cmd.Args)
}

// findHasMutatingAction reports whether a find argument list contains any
// side-effecting action from findMutatingActions as a real find primary.
//
// Tokens inside an -exec/-execdir payload are passed to the invoked command, not
// interpreted by find, so they are skipped — otherwise `find . -exec grep -e
// -delete {} \;` would be misread as having a find -delete action and prompt
// needlessly. We deliberately do not try to skip operands of other primaries
// (e.g. a file literally named "-delete" in `-name -delete`): that would risk
// skipping a genuine action, and the worst case here is only a harmless extra
// prompt, so we stay on the conservative side.
func findHasMutatingAction(args []string) bool {
	i := 0
	for i < len(args) {
		a := args[i]
		if a == "-exec" || a == "-execdir" {
			start := i + 1
			j := start
			for j < len(args) && !isFindExecTerminator(args, start, j) {
				j++
			}
			i = j + 1 // skip the payload and its terminator
			continue
		}
		if findMutatingActions[a] {
			return true
		}
		i++
	}
	return false
}

// findExecInners extracts the command(s) run by each -exec/-execdir action. The
// payload runs from the token after -exec up to the terminator (";", "\;", or
// "+"). The "{}" placeholder is left in place — it is harmless for classifying
// the command and matching allow patterns.
func findExecInners(args []string) []Command {
	var inners []Command
	for i := 0; i < len(args); {
		if args[i] != "-exec" && args[i] != "-execdir" {
			i++
			continue
		}
		start := i + 1
		j := start
		for j < len(args) && !isFindExecTerminator(args, start, j) {
			j++
		}
		if payload := args[start:j]; len(payload) > 0 {
			inners = append(inners, commandFromArgs(payload))
		}
		i = j + 1 // skip past the terminator
	}
	return inners
}

// isFindExecTerminator reports whether args[j] ends the -exec payload that began
// at index start. The shell-escaped semicolon (";" or "\;") always terminates. A
// "+" terminates only in the batching form `... {} +`, i.e. when the immediately
// preceding payload token is "{}"; a "+" anywhere else is a literal argument to
// the command and must stay in the payload so deny/ask rules still see it.
func isFindExecTerminator(args []string, start, j int) bool {
	switch args[j] {
	case ";", `\;`:
		return true
	case "+":
		return j > start && args[j-1] == "{}"
	}
	return false
}

// commandFromArgs builds a Command from an already-tokenized argument slice. A
// name containing shell expansion ("$VAR", backticks) is treated as dynamic so
// it can never match a static allow rule.
func commandFromArgs(args []string) Command {
	c := Command{
		Args: args,
		Raw:  strings.Join(args, " "),
	}
	if len(args) > 0 {
		if strings.ContainsAny(args[0], "$`") {
			c.Dynamic = true
		} else {
			c.Name = args[0]
		}
	}
	return c
}

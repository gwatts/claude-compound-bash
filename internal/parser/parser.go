// Package parser wraps mvdan.cc/sh/v3/syntax to extract all executable
// commands from a bash command string.
package parser

import (
	"fmt"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Command represents a single executable command extracted from the AST.
type Command struct {
	// Name is the resolved command name (e.g. "git", "echo").
	// Empty if the command name is dynamic (variable expansion, command substitution).
	Name string
	// Args is the full command line as individual words (including Name as first element).
	Args []string
	// Raw is the original source text of the command.
	Raw string
	// Dynamic is true if the command name cannot be statically determined.
	Dynamic bool
}

// String returns the command as "name arg1 arg2 ...".
func (c Command) String() string {
	if c.Raw != "" {
		return c.Raw
	}
	return strings.Join(c.Args, " ")
}

// Parse parses a bash command string and returns all executable commands
// found via a full AST walk. Returns an error if the command cannot be parsed
// — callers should deny (fail closed) on error.
func Parse(command string) ([]Command, error) {
	r := strings.NewReader(command)
	parser := syntax.NewParser(syntax.KeepComments(false))
	file, err := parser.Parse(r, "")
	if err != nil {
		return nil, fmt.Errorf("parse failed: %w", err)
	}

	var commands []Command
	printer := syntax.NewPrinter()

	syntax.Walk(file, func(node syntax.Node) bool {
		switch x := node.(type) {
		case *syntax.CallExpr:
			if len(x.Args) == 0 {
				// Pure assignment (e.g. FOO=bar) with no command name.
				// The Walk will recurse into Assigns, and any CmdSubst
				// in the RHS will be visited as its own CallExpr.
				return true
			}
			cmd := extractCallExpr(x, printer)
			commands = append(commands, cmd)

		case *syntax.DeclClause:
			// export/declare/local/readonly/typeset
			cmd := extractDeclClause(x, printer)
			commands = append(commands, cmd)
		}
		return true
	})

	return commands, nil
}

func extractCallExpr(call *syntax.CallExpr, printer *syntax.Printer) Command {
	args := make([]string, 0, len(call.Args))
	for _, word := range call.Args {
		args = append(args, wordToString(word, printer))
	}

	cmd := Command{
		Args: args,
		Raw:  printNode(printer, call),
	}

	if len(call.Args) > 0 {
		firstWord := call.Args[0]
		if isLiteralWord(firstWord) {
			cmd.Name = wordToString(firstWord, printer)
		} else {
			cmd.Dynamic = true
		}
	}

	return cmd
}

func extractDeclClause(decl *syntax.DeclClause, printer *syntax.Printer) Command {
	cmd := Command{
		Name: decl.Variant.Value, // "export", "declare", "local", etc.
		Raw:  printNode(printer, decl),
	}

	args := []string{decl.Variant.Value}
	for _, assign := range decl.Args {
		args = append(args, printNode(printer, assign))
	}
	cmd.Args = args

	return cmd
}

// isLiteralWord returns true if a word consists only of Lit parts (no expansions).
func isLiteralWord(w *syntax.Word) bool {
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			// plain text — fine
		case *syntax.SglQuoted:
			// 'literal' — fine
		case *syntax.DblQuoted:
			// "..." is fine only if contents are all Lit
			for _, inner := range p.Parts {
				if _, ok := inner.(*syntax.Lit); !ok {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

func wordToString(w *syntax.Word, printer *syntax.Printer) string {
	return printNode(printer, w)
}

func printNode(printer *syntax.Printer, node syntax.Node) string {
	var sb strings.Builder
	if err := printer.Print(&sb, node); err != nil {
		return "<unprintable>"
	}
	return sb.String()
}

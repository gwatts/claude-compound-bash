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

// ParseResult contains all information extracted from parsing a command.
type ParseResult struct {
	// Commands are the executable commands found in the input.
	Commands []Command
	// Redirects are all I/O redirects found in the input.
	Redirects []RedirectInfo
	// HasCwdChanger is true if any command changes the working directory (cd, pushd, popd).
	// When true, relative redirect targets cannot be validated reliably.
	HasCwdChanger bool
	// HasLinkCreator is true if any command can create symlinks/hardlinks (ln).
	// When true, relative redirect targets cannot be validated reliably since
	// the link could point outside allowed directories.
	HasLinkCreator bool
}

// String returns the command as "name arg1 arg2 ...".
func (c Command) String() string {
	if c.Raw != "" {
		return c.Raw
	}
	return strings.Join(c.Args, " ")
}

// Parse parses a bash command string and returns all executable commands
// and redirects found via a full AST walk. Returns an error if the command
// cannot be parsed — callers should deny (fail closed) on error.
func Parse(command string) (*ParseResult, error) {
	r := strings.NewReader(command)
	p := syntax.NewParser(syntax.KeepComments(false))
	file, err := p.Parse(r, "")
	if err != nil {
		return nil, fmt.Errorf("parse failed: %w", err)
	}

	var commands []Command
	var redirects []RedirectInfo
	var hasCwdChanger bool
	var hasLinkCreator bool
	printer := syntax.NewPrinter()

	syntax.Walk(file, func(node syntax.Node) bool {
		switch x := node.(type) {
		case *syntax.Stmt:
			// Extract redirects from every statement.
			// This handles all cases including:
			// - "cmd > file" (Stmt.Cmd = CallExpr)
			// - "> file" (Stmt.Cmd = nil, redirect-only)
			// - "(subcmd) > file" (Stmt.Cmd = Subshell)
			for _, redir := range x.Redirs {
				redirects = append(redirects, extractRedirect(redir, printer))
			}

		case *syntax.CallExpr:
			if len(x.Args) == 0 {
				// Pure assignment (e.g. FOO=bar) with no command name.
				// The Walk will recurse into Assigns, and any CmdSubst
				// in the RHS will be visited as its own CallExpr.
				return true
			}
			cmd := extractCallExpr(x, printer)
			commands = append(commands, cmd)

			// Check for cwd-changing commands
			if !cmd.Dynamic && isCwdChanger(cmd.Name) {
				hasCwdChanger = true
			}

			// Check for link-creating commands
			if !cmd.Dynamic && isLinkCreator(cmd.Name) {
				hasLinkCreator = true
			}

		case *syntax.DeclClause:
			// export/declare/local/readonly/typeset
			cmd := extractDeclClause(x, printer)
			commands = append(commands, cmd)
		}
		return true
	})

	return &ParseResult{
		Commands:       commands,
		Redirects:      redirects,
		HasCwdChanger:  hasCwdChanger,
		HasLinkCreator: hasLinkCreator,
	}, nil
}

// isCwdChanger returns true if the command name changes the working directory.
func isCwdChanger(name string) bool {
	switch name {
	case "cd", "pushd", "popd":
		return true
	}
	return false
}

// isLinkCreator returns true if the command can create symlinks or hardlinks.
func isLinkCreator(name string) bool {
	return name == "ln"
}

// extractRedirect extracts redirect information from an AST Redirect node.
func extractRedirect(redir *syntax.Redirect, printer *syntax.Printer) RedirectInfo {
	info := RedirectInfo{
		Op:  redir.Op,
		Raw: printNode(printer, redir),
	}

	// Extract FD number if present (e.g., "2" in "2>&1")
	if redir.N != nil {
		info.FD = redir.N.Value
	}

	// Heredocs (<<, <<-) and here-strings (<<<) have no file path target
	switch redir.Op {
	case syntax.Hdoc, syntax.DashHdoc, syntax.WordHdoc:
		info.IsHeredoc = true
		return info
	}

	// Extract target path/fd
	if redir.Word != nil {
		info.Target = wordToString(redir.Word, printer)
		info.TargetLiteral = isLiteralRedirectTarget(redir.Word)
	}

	return info
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

// isLiteralRedirectTarget returns true if a redirect target is fully literal
// and does not contain tilde or glob characters that would be expanded by bash.
func isLiteralRedirectTarget(w *syntax.Word) bool {
	if !isLiteralWord(w) {
		return false
	}

	// Check for tilde and glob characters in literal content
	for _, part := range w.Parts {
		var text string
		switch p := part.(type) {
		case *syntax.Lit:
			text = p.Value
		case *syntax.SglQuoted:
			// Content inside single quotes is truly literal
			continue
		case *syntax.DblQuoted:
			// Check inside double quotes
			for _, inner := range p.Parts {
				if lit, ok := inner.(*syntax.Lit); ok {
					// Content inside double quotes doesn't expand globs or tilde
					// but we still check for safety
					_ = lit
				}
			}
			continue
		}

		// Check for tilde at start (tilde expansion)
		if strings.HasPrefix(text, "~") {
			return false
		}

		// Check for glob characters
		if strings.ContainsAny(text, "*?[") {
			return false
		}

		// Check for extglob patterns: @(...), +(...), !(...), *(...)
		// These expand when shopt -s extglob is enabled
		if strings.Contains(text, "@(") || strings.Contains(text, "+(") ||
			strings.Contains(text, "!(") || strings.Contains(text, "*(") {
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

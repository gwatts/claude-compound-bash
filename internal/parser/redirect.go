package parser

import "mvdan.cc/sh/v3/syntax"

// RedirectInfo represents a single I/O redirect extracted from the AST.
type RedirectInfo struct {
	// Op is the redirect operator (e.g., >, >>, <, <<, >&, etc.)
	Op syntax.RedirOperator
	// FD is the file descriptor number if specified (e.g., "2" in 2>&1).
	// Empty string if not specified.
	FD string
	// Target is the redirect target as a string (path or fd number).
	// Empty for heredocs (<<, <<-).
	Target string
	// TargetLiteral is true if Target is fully literal (no variable
	// expansions, globs, tilde, command substitution, etc.).
	TargetLiteral bool
	// IsHeredoc is true for heredoc (<<, <<-) and here-string (<<<) operators.
	IsHeredoc bool
	// Raw is the original source text of the redirect.
	Raw string
}

// IsOutput returns true if this is an output redirect (>, >>, >&, &>, etc.)
func (r *RedirectInfo) IsOutput() bool {
	switch r.Op {
	case syntax.RdrOut, // >
		syntax.AppOut,     // >>
		syntax.DplOut,     // >&
		syntax.RdrClob,    // >|
		syntax.AppClob,    // >>| (zsh)
		syntax.RdrAll,     // &>
		syntax.RdrAllClob, // &>| (zsh)
		syntax.AppAll:     // &>>
		return true
	}
	return false
}

// IsInput returns true if this is an input redirect (<, <<, <<<, <&, etc.)
func (r *RedirectInfo) IsInput() bool {
	switch r.Op {
	case syntax.RdrIn, // <
		syntax.RdrInOut, // <>
		syntax.DplIn,    // <&
		syntax.Hdoc,     // <<
		syntax.DashHdoc, // <<-
		syntax.WordHdoc: // <<<
		return true
	}
	return false
}

// IsFDDup returns true if this is fd-to-fd duplication (2>&1, <&0, etc.)
// with a numeric target (not a file path).
func (r *RedirectInfo) IsFDDup() bool {
	if r.Op != syntax.DplIn && r.Op != syntax.DplOut {
		return false
	}
	// Check if target is purely numeric (a file descriptor)
	// e.g., "2>&1" has target "1", but ">&file" has target "file"
	if r.Target == "" || r.Target == "-" {
		// >&- closes the fd, treat as fd dup (safe)
		return true
	}
	for _, c := range r.Target {
		if c < '0' || c > '9' {
			return false // Contains non-digit, it's a filename
		}
	}
	return true
}

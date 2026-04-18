package parser

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// RedirectSafety classifies how a redirect should be handled.
type RedirectSafety int

const (
	// RedirectSafe means the redirect can be auto-allowed (fd dup, /dev/null, heredoc).
	RedirectSafe RedirectSafety = iota
	// RedirectCheckPath means the target path needs validation against cwd and allowed dirs.
	RedirectCheckPath
	// RedirectAsk means the redirect requires user confirmation (dynamic target).
	RedirectAsk
)

// safeDevices are device files that are always safe for redirection.
// Note: /dev/fd/* is NOT included because it can reference arbitrary files.
var safeDevices = []string{
	"/dev/null",
	"/dev/stdin",
	"/dev/stdout",
	"/dev/stderr",
	"/dev/zero",
	"/dev/random",
	"/dev/urandom",
}

// caseSensitiveFS indicates whether the filesystem is case-sensitive.
// macOS (APFS) and Windows are typically case-insensitive.
var caseSensitiveFS = runtime.GOOS != "darwin" && runtime.GOOS != "windows"

// ClassifyRedirect returns the safety classification for a redirect.
func ClassifyRedirect(r *RedirectInfo) RedirectSafety {
	// FD-to-FD duplications are always safe (no file access)
	if r.IsFDDup() {
		return RedirectSafe
	}

	// Heredocs have no file target
	if r.IsHeredoc {
		return RedirectSafe
	}

	// Dynamic targets (variables, globs, tilde, command substitution) require ask
	if !r.TargetLiteral {
		return RedirectAsk
	}

	// Literal target - needs path-based validation
	return RedirectCheckPath
}

// IsSafeDevice returns true if path is a known-safe device file.
func IsSafeDevice(path string) bool {
	normalized := normalizePath(path)
	for _, dev := range safeDevices {
		if pathEqual(normalized, dev) {
			return true
		}
	}
	return false
}

// protectedSegments are directory names that should never be written to,
// whether at the root or nested (e.g., submodule/.git/config).
var protectedSegments = []string{".git", ".claude"}

// IsProtectedPath returns true if the resolved path targets a protected
// directory inside cwd (.git, .claude) at any nesting level.
func IsProtectedPath(resolvedPath, cwd string) bool {
	// Resolve cwd using deepest ancestor resolution to handle symlinks
	// even when cwd doesn't fully exist
	cwdResolved, _ := resolveDeepestAncestor(cwd)

	// Check if path is inside cwd first
	if !isInsideDir(resolvedPath, cwdResolved) {
		return false // Not inside cwd, protected check doesn't apply
	}

	// Get relative path from cwd
	rel, err := filepath.Rel(cwdResolved, resolvedPath)
	if err != nil {
		return false
	}

	// Check if any path segment is a protected directory
	return containsProtectedSegment(rel)
}

// containsProtectedSegment returns true if any component of the path
// is a protected directory name (.git, .claude).
func containsProtectedSegment(path string) bool {
	// Split path into components
	parts := strings.Split(filepath.Clean(path), string(filepath.Separator))
	for _, part := range parts {
		for _, protected := range protectedSegments {
			if pathEqual(part, protected) {
				return true
			}
		}
	}
	return false
}

// ResolvePath resolves a path to an absolute path with symlinks resolved.
// If path is relative, it's resolved relative to cwd.
// For paths that don't fully exist, it walks up to find the deepest existing
// ancestor, resolves symlinks on that ancestor, then appends the remaining suffix.
// This prevents symlink escape attacks where a symlinked directory contains
// a non-existent subdirectory.
func ResolvePath(path, cwd string) (string, error) {
	// Handle relative paths
	if !filepath.IsAbs(path) {
		path = filepath.Join(cwd, path)
	}

	// Clean the path first
	path = filepath.Clean(path)

	// Try to resolve symlinks on the full path
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		return resolved, nil
	}

	// Path doesn't fully exist - walk up to find the deepest existing ancestor.
	// This is critical for security: if cwd/link -> /etc and we're writing to
	// cwd/link/newdir/file, we must resolve cwd/link to /etc, not just return
	// the unresolved path.
	return resolveDeepestAncestor(path)
}

// resolveDeepestAncestor walks up the path to find the deepest existing ancestor,
// resolves symlinks on that ancestor, then appends the remaining suffix.
func resolveDeepestAncestor(path string) (string, error) {
	// Split path into components
	path = filepath.Clean(path)

	// Walk up until we find an existing path
	current := path
	var suffix []string

	for current != "/" && current != "." {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			// Found an existing ancestor - append the suffix
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			return resolved, nil
		}

		// Move up one level
		suffix = append(suffix, filepath.Base(current))
		current = filepath.Dir(current)
	}

	// Reached root without finding an existing path
	// Try to resolve root itself (handles cases like /private on macOS)
	resolved, err := filepath.EvalSymlinks(current)
	if err != nil {
		resolved = current
	}

	// Append all suffix components
	for i := len(suffix) - 1; i >= 0; i-- {
		resolved = filepath.Join(resolved, suffix[i])
	}

	return resolved, nil
}

// NormalizeTmpPath handles macOS /tmp -> /private/tmp mapping.
func NormalizeTmpPath(path string) string {
	if runtime.GOOS == "darwin" {
		if path == "/tmp" || strings.HasPrefix(path, "/tmp/") {
			return "/private" + path
		}
	}
	return path
}

// ExpandAdditionalDirs expands a list of additional allowed directories,
// handling special cases like /tmp on macOS.
// Returns an error if any path is not absolute.
func ExpandAdditionalDirs(dirs []string) ([]string, error) {
	if len(dirs) == 0 {
		return nil, nil
	}

	result := make([]string, 0, len(dirs)*2)
	for _, dir := range dirs {
		// Require absolute paths to avoid ambiguity about what cwd they're relative to
		if !filepath.IsAbs(dir) {
			return nil, fmt.Errorf("additionalOutputDirs must be absolute paths, got %q", dir)
		}

		// Clean and normalize the path
		expanded := filepath.Clean(dir)
		expanded = NormalizeTmpPath(expanded)
		result = append(result, expanded)

		// If /tmp is allowed, also allow $TMPDIR location
		if dir == "/tmp" || dir == "/tmp/" {
			if tmpdir := os.Getenv("TMPDIR"); tmpdir != "" {
				cleanTmpdir := filepath.Clean(tmpdir)
				// Avoid duplicates
				if cleanTmpdir != expanded {
					result = append(result, cleanTmpdir)
				}
			}
		}
	}

	return result, nil
}

// IsInsideAllowedDir checks if a resolved path is inside the cwd or any additional allowed directory.
// Both the path and cwd should be resolved (symlinks expanded) for accurate comparison.
func IsInsideAllowedDir(resolvedPath, cwd string, additionalDirs []string) bool {
	// Resolve cwd using deepest ancestor resolution to handle symlinks
	// even when cwd doesn't fully exist (e.g., /tmp/nonexistent where /tmp -> /private/tmp)
	cwdResolved, _ := resolveDeepestAncestor(cwd)

	// Check cwd
	if isInsideDir(resolvedPath, cwdResolved) {
		return true
	}

	// Check additional directories (also resolve symlinks)
	for _, dir := range additionalDirs {
		dirResolved, _ := resolveDeepestAncestor(dir)
		if isInsideDir(resolvedPath, dirResolved) {
			return true
		}
	}

	return false
}

// normalizePath cleans a path for comparison purposes.
func normalizePath(path string) string {
	return filepath.Clean(path)
}

// pathEqual compares two paths for equality, respecting case sensitivity.
func pathEqual(a, b string) bool {
	if caseSensitiveFS {
		return a == b
	}
	return strings.EqualFold(a, b)
}

// isInsideDir checks if path is inside or equal to dir.
func isInsideDir(path, dir string) bool {
	if caseSensitiveFS {
		return path == dir || strings.HasPrefix(path, dir+string(filepath.Separator))
	}
	pathLower := strings.ToLower(path)
	dirLower := strings.ToLower(dir)
	return pathLower == dirLower || strings.HasPrefix(pathLower, dirLower+string(filepath.Separator))
}

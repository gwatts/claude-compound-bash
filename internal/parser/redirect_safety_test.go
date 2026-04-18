package parser

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsSafeDevice(t *testing.T) {
	tests := []struct {
		path   string
		safe   bool
		reason string
	}{
		{"/dev/null", true, "/dev/null is safe"},
		{"/dev/stdin", true, "/dev/stdin is safe"},
		{"/dev/stdout", true, "/dev/stdout is safe"},
		{"/dev/stderr", true, "/dev/stderr is safe"},
		{"/dev/zero", true, "/dev/zero is safe"},
		{"/dev/random", true, "/dev/random is safe"},
		{"/dev/urandom", true, "/dev/urandom is safe"},
		{"/dev/fd/3", false, "/dev/fd/* is NOT safe"},
		{"/dev/tty", false, "/dev/tty is not in safe list"},
		{"/etc/passwd", false, "not a device"},
		{"output.txt", false, "not a device"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.safe, IsSafeDevice(tt.path), tt.reason)
		})
	}
}

func TestIsProtectedPath(t *testing.T) {
	// Use a real temp directory to avoid path resolution issues
	cwd := t.TempDir()
	cwdResolved, _ := filepath.EvalSymlinks(cwd)

	tests := []struct {
		relPath   string
		protected bool
		reason    string
	}{
		{".git/config", true, ".git is protected"},
		{".git", true, ".git itself is protected"},
		{".claude/settings.json", true, ".claude is protected"},
		{".claude", true, ".claude itself is protected"},
		{"src/main.go", false, "normal file is not protected"},
		{"output.txt", false, "normal file is not protected"},
		{".gitignore", false, ".gitignore is not .git"},
		// Nested protected paths (submodules, vendored repos)
		{"submodule/.git/config", true, "nested .git is protected"},
		{"vendor/repo/.git/hooks/pre-commit", true, "deeply nested .git is protected"},
		{"nested/.claude/settings.json", true, "nested .claude is protected"},
		{"a/b/c/.git/d", true, "deeply nested .git path component is protected"},
	}

	for _, tt := range tests {
		t.Run(tt.relPath, func(t *testing.T) {
			// Build resolved absolute path
			resolvedPath := filepath.Join(cwdResolved, tt.relPath)
			assert.Equal(t, tt.protected, IsProtectedPath(resolvedPath, cwd), tt.reason)
		})
	}

	// Test path outside cwd
	t.Run("outside cwd", func(t *testing.T) {
		etcResolved, _ := filepath.EvalSymlinks("/etc")
		assert.False(t, IsProtectedPath(filepath.Join(etcResolved, "passwd"), cwd), "outside cwd is not protected")
	})
}

func TestIsInsideAllowedDir(t *testing.T) {
	// Use real temp directories to avoid path resolution issues
	cwd := t.TempDir()
	cwdResolved, _ := filepath.EvalSymlinks(cwd)

	// Create a subdirectory
	subdir := filepath.Join(cwd, "subdir")
	require.NoError(t, os.MkdirAll(subdir, 0755))

	// Create another temp dir for "additional" testing
	additionalDir := t.TempDir()
	additionalDirResolved, _ := filepath.EvalSymlinks(additionalDir)

	tests := []struct {
		path    string
		allowed bool
		reason  string
	}{
		{filepath.Join(cwdResolved, "output.txt"), true, "inside cwd"},
		{filepath.Join(cwdResolved, "subdir", "file.txt"), true, "inside cwd subdir"},
		{cwdResolved, true, "cwd itself"},
		{filepath.Join(additionalDirResolved, "file.txt"), true, "inside additional dir"},
	}

	additionalDirs := []string{additionalDir}

	for _, tt := range tests {
		t.Run(tt.reason, func(t *testing.T) {
			assert.Equal(t, tt.allowed, IsInsideAllowedDir(tt.path, cwd, additionalDirs), tt.reason)
		})
	}

	// Test path outside allowed dirs
	t.Run("outside allowed dirs", func(t *testing.T) {
		etcResolved, _ := filepath.EvalSymlinks("/etc")
		assert.False(t, IsInsideAllowedDir(filepath.Join(etcResolved, "passwd"), cwd, additionalDirs), "not in allowed dirs")
	})
}

func TestExpandAdditionalDirs(t *testing.T) {
	result, err := ExpandAdditionalDirs(nil)
	require.NoError(t, err)
	assert.Nil(t, result, "nil input returns nil")

	result, err = ExpandAdditionalDirs([]string{})
	require.NoError(t, err)
	assert.Nil(t, result, "empty input returns nil")

	result, err = ExpandAdditionalDirs([]string{"/opt/logs"})
	require.NoError(t, err)
	assert.Equal(t, []string{"/opt/logs"}, result, "simple path unchanged")

	// Relative paths should be rejected
	_, err = ExpandAdditionalDirs([]string{"logs"})
	assert.Error(t, err, "relative path should be rejected")
	assert.Contains(t, err.Error(), "absolute paths")

	_, err = ExpandAdditionalDirs([]string{"/opt/logs", "relative/path"})
	assert.Error(t, err, "mixed paths with relative should be rejected")

	if runtime.GOOS == "darwin" {
		result, err = ExpandAdditionalDirs([]string{"/tmp"})
		require.NoError(t, err)
		assert.Contains(t, result, "/private/tmp", "macOS /tmp normalized")

		// Also check that $TMPDIR is added if /tmp is in the list
		if tmpdir := os.Getenv("TMPDIR"); tmpdir != "" {
			assert.Contains(t, result, filepath.Clean(tmpdir), "macOS $TMPDIR added")
		}
	}
}

func TestNormalizeTmpPath(t *testing.T) {
	if runtime.GOOS == "darwin" {
		assert.Equal(t, "/private/tmp", NormalizeTmpPath("/tmp"))
		assert.Equal(t, "/private/tmp/file.txt", NormalizeTmpPath("/tmp/file.txt"))
	} else {
		assert.Equal(t, "/tmp", NormalizeTmpPath("/tmp"))
		assert.Equal(t, "/tmp/file.txt", NormalizeTmpPath("/tmp/file.txt"))
	}

	// Other paths unchanged
	assert.Equal(t, "/var/log", NormalizeTmpPath("/var/log"))
}

func TestResolvePath(t *testing.T) {
	// Use temp directory for reliable cross-platform testing
	tmpDir := t.TempDir()
	projectDir := filepath.Join(tmpDir, "project")
	require.NoError(t, os.MkdirAll(projectDir, 0755))

	// Test relative path resolution
	resolved, err := ResolvePath("output.txt", projectDir)
	require.NoError(t, err)
	// Resolve expected path to handle symlinks (e.g., /var -> /private/var on macOS)
	expectedDir, _ := filepath.EvalSymlinks(projectDir)
	assert.Equal(t, filepath.Join(expectedDir, "output.txt"), resolved)

	// Test absolute path with existing file
	resolved, err = ResolvePath("/etc/passwd", projectDir)
	require.NoError(t, err)
	expectedEtc, _ := filepath.EvalSymlinks("/etc")
	assert.Equal(t, filepath.Join(expectedEtc, "passwd"), resolved)

	// Test path with .. normalization
	otherDir := filepath.Join(tmpDir, "other")
	require.NoError(t, os.MkdirAll(otherDir, 0755))
	resolved, err = ResolvePath("../other/file.txt", projectDir)
	require.NoError(t, err)
	expectedOther, _ := filepath.EvalSymlinks(otherDir)
	assert.Equal(t, filepath.Join(expectedOther, "file.txt"), resolved)
}

func TestCaseSensitivity(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("case sensitivity test only runs on macOS")
	}

	// Use a real temp directory
	cwd := t.TempDir()
	cwdResolved, _ := filepath.EvalSymlinks(cwd)

	// Test protected path with different cases
	assert.True(t, IsProtectedPath(filepath.Join(cwdResolved, ".GIT", "config"), cwd), ".GIT should match .git on macOS")
	assert.True(t, IsProtectedPath(filepath.Join(cwdResolved, ".CLAUDE", "settings.json"), cwd), ".CLAUDE should match .claude on macOS")

	// Test safe device with different case
	assert.True(t, IsSafeDevice("/DEV/NULL"), "/DEV/NULL should match /dev/null on macOS")
}

func TestResolvePathSymlinkEscape(t *testing.T) {
	// Create a temp directory structure with a symlink
	tmpDir := t.TempDir()

	// Create a target directory outside the "project"
	targetDir := filepath.Join(tmpDir, "outside")
	require.NoError(t, os.MkdirAll(targetDir, 0755))

	// Create a project directory
	projectDir := filepath.Join(tmpDir, "project")
	require.NoError(t, os.MkdirAll(projectDir, 0755))

	// Create a symlink inside project that points outside
	linkPath := filepath.Join(projectDir, "link")
	require.NoError(t, os.Symlink(targetDir, linkPath))

	// Resolve expected paths (handles /var -> /private/var on macOS)
	targetDirResolved, _ := filepath.EvalSymlinks(targetDir)
	projectDirResolved, _ := filepath.EvalSymlinks(projectDir)

	// Test 1: Path through symlink to existing directory
	resolved, err := ResolvePath(filepath.Join(linkPath, ""), projectDir)
	require.NoError(t, err)
	assert.Equal(t, targetDirResolved, resolved, "symlink should resolve to target")

	// Test 2: Path through symlink to non-existent subdirectory
	// This is the critical security test - we must resolve the symlink
	// even though the final path doesn't exist
	resolved, err = ResolvePath(filepath.Join(linkPath, "newdir", "file.txt"), projectDir)
	require.NoError(t, err)
	expected := filepath.Join(targetDirResolved, "newdir", "file.txt")
	assert.Equal(t, expected, resolved, "symlink escape must be detected even with non-existent subdirs")

	// Verify the resolved path is NOT inside projectDir
	assert.False(t, IsInsideAllowedDir(resolved, projectDirResolved, nil),
		"resolved path should NOT be inside project dir after symlink resolution")
}

func TestResolvePathDeepNonExistent(t *testing.T) {
	// Create a temp directory
	tmpDir := t.TempDir()

	// Create a subdirectory
	subDir := filepath.Join(tmpDir, "existing")
	require.NoError(t, os.MkdirAll(subDir, 0755))

	// Resolve expected path (handles /var -> /private/var on macOS)
	subDirResolved, _ := filepath.EvalSymlinks(subDir)

	// Test resolving a path where multiple levels don't exist
	deepPath := filepath.Join(subDir, "a", "b", "c", "file.txt")
	resolved, err := ResolvePath(deepPath, tmpDir)
	require.NoError(t, err)

	// Should resolve the existing part and append the rest
	expected := filepath.Join(subDirResolved, "a", "b", "c", "file.txt")
	assert.Equal(t, expected, resolved)
}

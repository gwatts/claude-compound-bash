package logfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenAndLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	log, err := Open(path)
	require.NoError(t, err)

	log.Log("hello %s", "world")
	require.NoError(t, log.Close())

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(data), "hello world")
}

func TestOpenCreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "test.log")

	log, err := Open(path)
	require.NoError(t, err)
	require.NoError(t, log.Close())

	info, err := os.Stat(filepath.Dir(path))
	require.NoError(t, err)
	assert.True(t, info.IsDir())
	assert.Equal(t, os.FileMode(0700), info.Mode().Perm())
}

func TestOpenFilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	log, err := Open(path)
	require.NoError(t, err)
	require.NoError(t, log.Close())

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestOpenEnvOverride(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "env.log")
	t.Setenv("CLAUDE_COMPOUND_LOG", envPath)

	log, err := Open("")
	require.NoError(t, err)

	log.Log("via env")
	require.NoError(t, log.Close())

	data, err := os.ReadFile(envPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), "via env")
}

func TestLogTimestampFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	log, err := Open(path)
	require.NoError(t, err)

	log.Log("test message")
	require.NoError(t, log.Close())

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	line := strings.TrimSpace(string(data))
	// RFC3339 timestamps start with a year like "2026-"
	assert.Regexp(t, `^\d{4}-\d{2}-\d{2}T`, line)
}

func TestNopLogger(t *testing.T) {
	log := NopLogger()
	// Should not panic.
	log.Log("this goes nowhere: %d", 42)
	assert.NoError(t, log.Close())
}

func TestNilFileLogger(t *testing.T) {
	// Verify nil-safe behavior.
	log := &Logger{}
	log.Log("should not panic: %d", 42)
	assert.NoError(t, log.Close())
}

func TestDefaultPath(t *testing.T) {
	path, err := defaultPath()
	require.NoError(t, err)
	assert.Contains(t, path, ".claude")
	assert.Contains(t, path, "compound-bash.log")
}

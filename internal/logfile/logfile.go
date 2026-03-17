// Package logfile provides safe logging to a user-owned directory.
package logfile

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Logger writes timestamped log entries to a file with safe permissions.
type Logger struct {
	mu     sync.Mutex
	file   *os.File
	prefix string
}

// defaultPath returns the default log file path under ~/.claude/logs/.
func defaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".claude", "logs", "compound-bash.log"), nil
}

// Open opens or creates the log file at the given path with 0600 permissions
// in a 0700 directory. If path is empty, the default path is used.
// If the CLAUDE_COMPOUND_LOG environment variable is set, it overrides the path.
func Open(path string) (*Logger, error) {
	if envPath := os.Getenv("CLAUDE_COMPOUND_LOG"); envPath != "" {
		path = envPath
	}
	if path == "" {
		var err error
		path, err = defaultPath()
		if err != nil {
			return nil, err
		}
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create log dir: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}

	return &Logger{file: f}, nil
}

// SetPrefix sets a prefix that is included in every log line after the timestamp.
func (l *Logger) SetPrefix(prefix string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prefix = prefix
}

// Log writes a timestamped entry to the log file.
func (l *Logger) Log(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file == nil {
		return
	}
	msg := fmt.Sprintf(format, args...)
	ts := time.Now().Format(time.RFC3339)
	if l.prefix != "" {
		_, _ = fmt.Fprintf(l.file, "%s [%s] %s\n", ts, l.prefix, msg)
	} else {
		_, _ = fmt.Fprintf(l.file, "%s %s\n", ts, msg)
	}
}

// Close closes the log file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	return l.file.Close()
}

// NopLogger returns a logger that discards all output.
func NopLogger() *Logger {
	f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		// Should never happen, but if it does, use a nil-safe approach.
		return &Logger{}
	}
	return &Logger{file: f}
}

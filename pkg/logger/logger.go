// Package logger provides a zero-dependency, zero-knowledge structured logging utility
// for ZeroFeed CLI and Relay server using the Go standard library log/slog.
package logger

import (
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
)

// LogFormat represents the output format for logs.
type LogFormat string

const (
	FormatText LogFormat = "text"
	FormatJSON LogFormat = "json"
)

var (
	mu           sync.RWMutex
	defaultLog   *slog.Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	currentFmt   LogFormat    = FormatText
	currentLvl   slog.Level   = slog.LevelInfo
	outputWriter io.Writer    = os.Stderr
)

// Init initializes the global logger with the specified format, level, and destination writer.
// By default, logs write to os.Stderr so stdout remains pure for binary payload streaming.
func Init(formatStr, levelStr string) {
	InitWithWriter(formatStr, levelStr, os.Stderr)
}

// InitWithWriter initializes the global logger targeting a custom io.Writer (useful for testing).
func InitWithWriter(formatStr, levelStr string, w io.Writer) {
	mu.Lock()
	defer mu.Unlock()

	if w == nil {
		w = os.Stderr
	}
	outputWriter = w

	level := parseLevel(levelStr)
	currentLvl = level

	format := LogFormat(strings.ToLower(strings.TrimSpace(formatStr)))
	if format != FormatJSON {
		format = FormatText
	}
	currentFmt = format

	opts := &slog.HandlerOptions{
		Level: level,
	}

	var handler slog.Handler
	if format == FormatJSON {
		handler = slog.NewJSONHandler(w, opts)
	} else {
		handler = slog.NewTextHandler(w, opts)
	}

	defaultLog = slog.New(handler)
}

// parseLevel converts string level into slog.Level.
func parseLevel(levelStr string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(levelStr)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	case "info":
		fallthrough
	default:
		return slog.LevelInfo
	}
}

// Get returns the global slog.Logger instance.
func Get() *slog.Logger {
	mu.RLock()
	defer mu.RUnlock()
	return defaultLog
}

// Format returns the currently configured log format ("text" or "json").
func Format() LogFormat {
	mu.RLock()
	defer mu.RUnlock()
	return currentFmt
}

// Level returns the currently configured log level.
func Level() slog.Level {
	mu.RLock()
	defer mu.RUnlock()
	return currentLvl
}

// Debug logs a message at Debug level.
func Debug(msg string, args ...any) {
	Get().Debug(msg, args...)
}

// Info logs a message at Info level.
func Info(msg string, args ...any) {
	Get().Info(msg, args...)
}

// Warn logs a message at Warn level.
func Warn(msg string, args ...any) {
	Get().Warn(msg, args...)
}

// Error logs a message at Error level.
func Error(msg string, args ...any) {
	Get().Error(msg, args...)
}

// With returns a new Logger that includes the given attributes.
func With(args ...any) *slog.Logger {
	return Get().With(args...)
}

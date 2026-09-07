package logging

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Logger writes one JSON object per line and always adds the component field.
type Logger struct {
	component string
	logger    *slog.Logger
	closer    io.Closer
	mu        sync.Mutex
}

func New(component, path string) (*Logger, error) {
	var w io.Writer = os.Stderr
	var closer io.Closer
	if path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, err
		}
		w, closer = io.MultiWriter(os.Stderr, f), f
	}
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo})
	return &Logger{component: component, logger: slog.New(h), closer: closer}, nil
}

func (l *Logger) Close() error {
	if l.closer != nil {
		return l.closer.Close()
	}
	return nil
}

func (l *Logger) Info(sessionID, message string, attrs ...any) {
	attrs = append([]any{"component", l.component, "session_id", sessionID}, attrs...)
	l.logger.Info(message, attrs...)
}

func (l *Logger) Error(sessionID, message string, err error, attrs ...any) {
	attrs = append([]any{"component", l.component, "session_id", sessionID, "error", err.Error()}, attrs...)
	l.logger.Error(message, attrs...)
}

// Redact returns a safe marker for secrets. It is intentionally not reversible.
func Redact(value string) string {
	if value == "" {
		return ""
	}
	return "[REDACTED]"
}

// Event is useful when structured log records need to be returned through the UI.
type Event struct {
	Timestamp time.Time      `json:"timestamp"`
	Component string         `json:"component"`
	Level     string         `json:"level"`
	SessionID string         `json:"session_id,omitempty"`
	Message   string         `json:"message"`
	Fields    map[string]any `json:"fields,omitempty"`
}

func (e Event) JSON() string {
	b, _ := json.Marshal(e)
	return string(b)
}

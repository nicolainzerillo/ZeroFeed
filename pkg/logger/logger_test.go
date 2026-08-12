package logger_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/zerofeed/zerofeed/pkg/logger"
)

func TestLoggerTextFormat(t *testing.T) {
	buf := new(bytes.Buffer)
	logger.InitWithWriter("text", "info", buf)

	if logger.Format() != logger.FormatText {
		t.Fatalf("expected format %s, got %s", logger.FormatText, logger.Format())
	}
	if logger.Level() != slog.LevelInfo {
		t.Fatalf("expected level info, got %v", logger.Level())
	}

	logger.Info("relay server started", "port", 8443)

	out := buf.String()
	if !strings.Contains(out, "relay server started") || !strings.Contains(out, "port=8443") {
		t.Fatalf("unexpected text log output: %s", out)
	}
}

func TestLoggerJSONFormat(t *testing.T) {
	buf := new(bytes.Buffer)
	logger.InitWithWriter("json", "debug", buf)

	if logger.Format() != logger.FormatJSON {
		t.Fatalf("expected format %s, got %s", logger.FormatJSON, logger.Format())
	}
	if logger.Level() != slog.LevelDebug {
		t.Fatalf("expected level debug, got %v", logger.Level())
	}

	logger.Debug("session established", "session_id", "a1b2c3d4", "subscribers", 2)

	out := buf.Bytes()
	var fields map[string]any
	if err := json.Unmarshal(out, &fields); err != meNilErr(err) {
		t.Fatalf("failed to parse JSON log output: %v, raw output: %s", err, string(out))
	}

	if fields["msg"] != "session established" {
		t.Errorf("expected msg 'session established', got %v", fields["msg"])
	}
	if fields["level"] != "DEBUG" {
		t.Errorf("expected level 'DEBUG', got %v", fields["level"])
	}
	if fields["session_id"] != "a1b2c3d4" {
		t.Errorf("expected session_id 'a1b2c3d4', got %v", fields["session_id"])
	}
	if float64(2) != fields["subscribers"].(float64) {
		t.Errorf("expected subscribers 2, got %v", fields["subscribers"])
	}
}

func TestLoggerLevelFiltering(t *testing.T) {
	buf := new(bytes.Buffer)
	logger.InitWithWriter("json", "warn", buf)

	logger.Debug("this should be suppressed")
	logger.Info("this should also be suppressed")
	if buf.Len() > 0 {
		t.Fatalf("expected no output for logs below warn level, got: %s", buf.String())
	}

	logger.Warn("high memory watermark reached", "watermark_percent", 82.5)
	if buf.Len() == 0 {
		t.Fatalf("expected log output for warn level")
	}

	var fields map[string]any
	if err := json.Unmarshal(buf.Bytes(), &fields); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}
	if fields["level"] != "WARN" {
		t.Errorf("expected level WARN, got %v", fields["level"])
	}
}

func TestLoggerConcurrency(t *testing.T) {
	buf := new(bytes.Buffer)
	logger.InitWithWriter("json", "info", buf)

	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 50; j++ {
				logger.Info("concurrent log", "worker", id, "iteration", j)
				logger.Debug("suppressed log", "worker", id)
			}
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	if buf.Len() == 0 {
		t.Fatalf("expected concurrent log output")
	}
}

func meNilErr(err error) error {
	return err
}

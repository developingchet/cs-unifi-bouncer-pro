package logger

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/sirupsen/logrus"
)

func TestForwardLogrus(t *testing.T) {
	tests := []struct {
		name      string
		level     zerolog.Level
		logFn     func()
		wantLevel string
		wantMsg   string
	}{
		{"info passes at info", zerolog.InfoLevel, func() { logrus.WithField("k", "v").Info("hello") }, "info", "hello"},
		{"debug dropped at info", zerolog.InfoLevel, func() { logrus.Debug("hidden") }, "", ""},
		{"library debug dropped at debug", zerolog.DebugLevel, func() { logrus.Debug("wire dump") }, "", ""},
		{"library debug shown at trace", zerolog.TraceLevel, func() { logrus.Debug("wire dump") }, "trace", "wire dump"},
		{"warn keeps level", zerolog.DebugLevel, func() { logrus.Warn("careful") }, "warn", "careful"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			ForwardLogrus(zerolog.New(&buf).Level(tt.level))
			tt.logFn()
			if tt.wantMsg == "" {
				if buf.Len() != 0 {
					t.Fatalf("expected no output, got %q", buf.String())
				}
				return
			}
			var line map[string]any
			if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &line); err != nil {
				t.Fatalf("output is not one JSON line: %q", buf.String())
			}
			if line["level"] != tt.wantLevel || line["message"] != tt.wantMsg || line["component"] != "crowdsec-client" {
				t.Fatalf("unexpected line %v", line)
			}
		})
	}
}

func TestForwardLogrusRedacts(t *testing.T) {
	var buf bytes.Buffer
	ForwardLogrus(zerolog.New(NewRedactWriter(&buf)))
	logrus.WithField("api_key", "super-secret-value").Info("connecting")
	if strings.Contains(buf.String(), "super-secret-value") {
		t.Fatalf("secret leaked: %s", buf.String())
	}
}

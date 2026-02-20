package logger

import (
	"bytes"
	"strings"
	"testing"
)

func redact(input string) string {
	var buf bytes.Buffer
	w := NewRedactWriter(&buf)
	_, _ = w.Write([]byte(input))
	return buf.String()
}

func TestRedactPassword(t *testing.T) {
	cases := []struct {
		input    string
		contains string
	}{
		{`UNIFI_PASSWORD=SuperSecret123`, "UNIFI_PASSWORD="},
		{`"unifi_password":"mysecretpassword"`, `"unifi_password":"`},
		{`password=hunter2`, "password="},
	}
	for _, c := range cases {
		got := redact(c.input)
		if !strings.Contains(got, c.contains) {
			t.Errorf("should contain %q, got: %q", c.contains, got)
		}
		if strings.Contains(got, "SuperSecret123") ||
			strings.Contains(got, "mysecretpassword") ||
			strings.Contains(got, "hunter2") {
			t.Errorf("secret value should be redacted, got: %q", got)
		}
	}
}

func TestRedactAPIKey(t *testing.T) {
	input := `UNIFI_API_KEY=abcdef1234567890XYZ`
	got := redact(input)
	if strings.Contains(got, "abcdef1234567890XYZ") {
		t.Errorf("API key should be redacted, got: %q", got)
	}
	if !strings.Contains(got, "UNIFI_API_KEY=") {
		t.Errorf("key name should be preserved, got: %q", got)
	}
}

func TestRedactBearerToken(t *testing.T) {
	input := `Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9`
	got := redact(input)
	if strings.Contains(got, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9") {
		t.Errorf("Bearer token should be redacted, got: %q", got)
	}
	if !strings.Contains(got, "Bearer") {
		t.Errorf("Bearer keyword should be preserved, got: %q", got)
	}
}

func TestPassthroughCleanString(t *testing.T) {
	input := `{"status": "ok", "ip": "1.2.3.4", "count": 42}`
	got := redact(input)
	if got != input {
		t.Errorf("clean string should pass through unchanged, got: %q", got)
	}
}

func TestRedactLAPIKey(t *testing.T) {
	input := `crowdsec_lapi_key=mysupersecretlapikey123`
	got := redact(input)
	if strings.Contains(got, "mysupersecretlapikey123") {
		t.Errorf("LAPI key should be redacted, got: %q", got)
	}
}

func TestWriteReturnLength(t *testing.T) {
	var buf bytes.Buffer
	w := NewRedactWriter(&buf)
	input := []byte("hello world UNIFI_PASSWORD=secret")
	n, err := w.Write(input)
	if err != nil {
		t.Fatal(err)
	}
	// Should return original length
	if n != len(input) {
		t.Errorf("Write should return original length %d, got %d", len(input), n)
	}
}

func TestRedactXApiKeyHeader(t *testing.T) {
	input := `X-Api-Key: my-unifi-key-value-12345678`
	got := redact(input)
	if strings.Contains(got, "my-unifi-key-value-12345678") {
		t.Errorf("X-Api-Key value should be redacted, got: %q", got)
	}
}

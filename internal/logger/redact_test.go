package logger

import (
	"bytes"
	"encoding/json"
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

func TestRedactPreservesStructuredLog(t *testing.T) {
	input := `{"password":"secret,with\"quote","status":"ok","api_key":"abcdef1234567890"}`
	got := redact(input)
	var fields map[string]string
	if err := json.Unmarshal([]byte(got), &fields); err != nil {
		t.Fatalf("redacted output is not JSON: %v; output: %s", err, got)
	}
	if fields["password"] != "[REDACTED]" || fields["api_key"] != "[REDACTED]" || fields["status"] != "ok" {
		t.Fatalf("unexpected redacted output: %s", got)
	}
}

func TestRedactSessionAndTokens(t *testing.T) {
	tests := []struct{ name, input, secret string }{
		{"cookie header", `Cookie: unifises=s3ss10nv4lue`, "s3ss10nv4lue"},
		{"set-cookie json", `{"set-cookie":"TOKEN=eyJhbGciOiJIUzI1NiJ9.abc; Path=/"}`, "eyJhbGciOiJIUzI1NiJ9"},
		{"csrf header", `X-Csrf-Token: 0f1e2d3c4b5a`, "0f1e2d3c4b5a"},
		{"updated csrf header", `"X-Updated-Csrf-Token":"9a8b7c6d"`, "9a8b7c6d"},
		{"url token", `GET https://feeds.example/list.txt?token=feedsecret99 failed`, "feedsecret99"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := redact(tt.input); strings.Contains(got, tt.secret) {
				t.Errorf("secret not redacted: %q", got)
			}
		})
	}
}

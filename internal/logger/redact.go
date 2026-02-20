package logger

import (
	"bytes"
	"io"
	"regexp"
)

// RedactWriter wraps an io.Writer and masks sensitive values before writing.
// It redacts UNIFI_PASSWORD values, API keys, and Bearer tokens from log lines.
type RedactWriter struct {
	w          io.Writer
	patterns   []*regexp.Regexp
	redactWith string
}

var defaultPatterns = []*regexp.Regexp{
	// Password in key=value or "key":"value" form
	regexp.MustCompile(`(?i)(unifi_password["'\s:=]+)\S+`),
	regexp.MustCompile(`(?i)(password["'\s:=]+)\S+`),
	// API keys: long alphanumeric strings after "key", "apikey", "api_key"
	regexp.MustCompile(`(?i)(api[_-]?key["'\s:=]+)[A-Za-z0-9\-_]{16,}`),
	regexp.MustCompile(`(?i)(unifi_api_key["'\s:=]+)\S+`),
	// Bearer tokens in Authorization headers
	regexp.MustCompile(`(?i)(Bearer\s+)[A-Za-z0-9\-_\.]+`),
	// crowdsec LAPI key patterns
	regexp.MustCompile(`(?i)(lapi[_-]?key["'\s:=]+)\S+`),
	regexp.MustCompile(`(?i)(bouncer[_-]?api[_-]?key["'\s:=]+)\S+`),
	// X-Api-Key header
	regexp.MustCompile(`(?i)(X-Api-Key["'\s:=]+)\S+`),
}

// NewRedactWriter returns a RedactWriter that applies all default sensitive patterns.
func NewRedactWriter(w io.Writer) *RedactWriter {
	return &RedactWriter{
		w:          w,
		patterns:   defaultPatterns,
		redactWith: "[REDACTED]",
	}
}

// Write applies all redaction patterns before forwarding to the underlying writer.
func (r *RedactWriter) Write(p []byte) (int, error) {
	sanitized := p
	for _, re := range r.patterns {
		sanitized = re.ReplaceAll(sanitized, appendRedacted(re, r.redactWith))
	}
	n, err := r.w.Write(sanitized)
	// Return original length so callers don't get short-write errors
	// even if redaction changed the byte count.
	if n > len(sanitized) {
		n = len(sanitized)
	}
	if err != nil {
		return n, err
	}
	return len(p), nil
}

// appendRedacted builds a replacement []byte that keeps capture group $1 + redactWith.
func appendRedacted(re *regexp.Regexp, redact string) []byte {
	// All our patterns have exactly one capture group for the key/prefix.
	var buf bytes.Buffer
	buf.WriteString("${1}")
	buf.WriteString(redact)
	return buf.Bytes()
}

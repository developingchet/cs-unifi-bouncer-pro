package logger

import (
	"bytes"
	"io"
	"regexp"
)

// RedactWriter wraps an io.Writer and masks sensitive values before writing.
// It redacts passwords, API keys, session cookies, CSRF and other tokens, and
// Bearer tokens from log lines.
type RedactWriter struct {
	w io.Writer
}

var secretField = regexp.MustCompile(`(?i)((?:unifi_password|password|unifi_api_key|crowdsec_lapi_key|lapi[_-]?key|bouncer[_-]?api[_-]?key|x-api-key|api[_-]?key|(?:set-)?cookie|unifises|token)["']?\s*[:=]\s*)("(?:\\.|[^"\\])*"|'[^']*'|[^\s,}\]]+)`)
var bearerToken = regexp.MustCompile(`(?i)(Bearer\s+)[A-Za-z0-9_\-.]+`)

// NewRedactWriter returns a RedactWriter that applies all default sensitive patterns.
func NewRedactWriter(w io.Writer) *RedactWriter {
	return &RedactWriter{w: w}
}

// Write applies all redaction patterns before forwarding to the underlying writer.
func (r *RedactWriter) Write(p []byte) (int, error) {
	sanitized := secretField.ReplaceAllFunc(p, redactField)
	sanitized = bearerToken.ReplaceAll(sanitized, []byte("${1}[REDACTED]"))
	n, err := r.w.Write(sanitized)
	if err == nil && n != len(sanitized) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return n, err
	}
	return len(p), nil
}

func redactField(match []byte) []byte {
	indices := secretField.FindSubmatchIndex(match)
	prefix := match[indices[2]:indices[3]]
	value := match[indices[4]:indices[5]]
	var out bytes.Buffer
	out.Write(prefix)
	if len(value) > 1 && (value[0] == '"' || value[0] == '\'') {
		out.WriteByte(value[0])
		out.WriteString("[REDACTED]")
		out.WriteByte(value[0])
	} else {
		out.WriteString("[REDACTED]")
	}
	return out.Bytes()
}

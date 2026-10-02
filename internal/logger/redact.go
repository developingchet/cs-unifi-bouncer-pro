package logger

import (
	"bytes"
	"io"
	"regexp"
)

// RedactWriter wraps an io.Writer and masks sensitive values before writing.
// It redacts passwords, API keys, session cookies, CSRF and other tokens,
// Authorization credentials, and user info embedded in URLs from log lines.
type RedactWriter struct {
	w io.Writer
}

// valueTail matches what follows a "key:" or "key=" separator: a JSON string
// escaped inside another JSON string, a quoted string, or a bare token that
// ends at whitespace or a structural character.
const valueTail = `(\\"(?:[^"\\]|\\[^"])*\\"|"(?:\\.|[^"\\])*"|'[^']*'|[^\s,}\]]+)`

// keySep matches the end of a field name, including the quote that closes it
// (backslash-escaped when the line is itself a JSON string value), and the
// separator after it.
const keySep = `(?:\\?["'])?\s*[:=]\s*`

var secretField = regexp.MustCompile(`(?i)((?:unifi_password|password|unifi_api_key|crowdsec_lapi_key|lapi[_-]?key|bouncer[_-]?api[_-]?key|x-api-key|api[_-]?key|unifises|token)` + keySep + `)` + valueTail)

// cookieField covers Cookie and Set-Cookie. An unquoted header value is a
// ";"-separated list of pairs, any of which can carry a session.
var cookieField = regexp.MustCompile(`(?i)((?:set-)?cookie` + keySep + `)(\\"(?:[^"\\]|\\[^"])*\\"|"(?:\\.|[^"\\])*"|'[^']*'|[^\s;,}\]]+(?:;[ \t]*[^\s;,}\]]+)*;?)`)

// bearerToken covers the RFC 6750 token alphabet, which includes the "+", "/"
// and "=" of standard base64.
var bearerToken = regexp.MustCompile(`(?i)(Bearer\s+)[A-Za-z0-9\-._~+/]+=*`)

// authorizationValue covers the credential in an Authorization header sent
// under a scheme other than Bearer, such as Basic, or under no scheme.
var authorizationValue = regexp.MustCompile(`(?i)((?:proxy-)?authorization` + keySep + `(?:\\?["'])?(?:(?:bearer|basic|token|apikey|negotiate|ntlm)\s+)?)[^\s"',}\\]+`)

// urlUserInfo covers the user:password@ part of a URL authority. The class
// stops at "/", "?" and "#" so an "@" in a path or query is left alone.
var urlUserInfo = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.\-]*://)[^\s/?#@"'\\]+@`)

// NewRedactWriter returns a RedactWriter that applies all default sensitive patterns.
func NewRedactWriter(w io.Writer) *RedactWriter {
	return &RedactWriter{w: w}
}

// Write applies all redaction patterns before forwarding to the underlying writer.
func (r *RedactWriter) Write(p []byte) (int, error) {
	sanitized := cookieField.ReplaceAllFunc(p, redactFieldWith(cookieField))
	sanitized = secretField.ReplaceAllFunc(sanitized, redactFieldWith(secretField))
	sanitized = bearerToken.ReplaceAll(sanitized, []byte("${1}[REDACTED]"))
	sanitized = authorizationValue.ReplaceAll(sanitized, []byte("${1}[REDACTED]"))
	sanitized = urlUserInfo.ReplaceAll(sanitized, []byte("${1}[REDACTED]@"))
	n, err := r.w.Write(sanitized)
	if err == nil && n != len(sanitized) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return n, err
	}
	return len(p), nil
}

// redactFieldWith returns a replacer for re, whose first group is the field
// name and separator and whose second group is the value. The quotes around
// the value are kept so structured output stays parseable.
func redactFieldWith(re *regexp.Regexp) func([]byte) []byte {
	return func(match []byte) []byte {
		indices := re.FindSubmatchIndex(match)
		prefix := match[indices[2]:indices[3]]
		value := match[indices[4]:indices[5]]
		var out bytes.Buffer
		out.Write(prefix)
		switch {
		case bytes.HasPrefix(value, []byte(`\"`)) && len(value) >= 4:
			out.WriteString(`\"[REDACTED]\"`)
		case len(value) > 1 && (value[0] == '"' || value[0] == '\''):
			out.WriteByte(value[0])
			out.WriteString("[REDACTED]")
			out.WriteByte(value[0])
		default:
			out.WriteString("[REDACTED]")
		}
		return out.Bytes()
	}
}

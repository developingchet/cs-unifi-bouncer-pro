package logger

import (
	"strings"
	"testing"
)

// FuzzSafeURL checks that a credential carried in the user info, query or
// fragment of a URL never reaches the log line, whatever host and path
// surround it.
func FuzzSafeURL(f *testing.F) {
	const secret = "s3cr3t-7f2Q"
	f.Add("feeds.example.com", "/list.txt")
	f.Add("hooks.slack.com", "/services/T000/B000")
	f.Add("127.0.0.1:8080", "/v1/decisions")
	f.Add("a@b", "/@")
	f.Add("x?", "#/")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, host, path string) {
		if strings.Contains(host+path, secret) {
			return
		}
		raw := "https://user:" + secret + "@" + host + path + "?token=" + secret + "#" + secret
		if out := SafeURL(raw); strings.Contains(out, secret) {
			t.Fatalf("SafeURL(%q) = %q leaks the credential", raw, out)
		}
	})
}

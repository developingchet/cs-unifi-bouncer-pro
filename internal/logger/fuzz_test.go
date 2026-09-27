package logger

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

// FuzzRedactWriterBearer checks that no 12-character run of a Bearer token
// survives redaction. Tokens use the full RFC 6750 alphabet, including the
// "+", "/" and "=" of standard base64.
func FuzzRedactWriterBearer(f *testing.F) {
	f.Add("Authorization: ", "\n", []byte("0123456789abcdef"))
	f.Add(`{"header":"`, `"}`, []byte{0xfb, 0xff, 0xbf, 0xfe, 0xef, 0xff, 0xfb, 0xff, 0xbf, 0xfe, 0xef, 0xff})
	f.Add("", "", []byte{})
	f.Fuzz(func(t *testing.T, before, after string, raw []byte) {
		if len(raw) < 12 {
			return
		}
		token := base64.StdEncoding.EncodeToString(raw)
		var out bytes.Buffer
		if _, err := NewRedactWriter(&out).Write([]byte(before + "Bearer " + token + after)); err != nil {
			t.Fatal(err)
		}
		const window = 12
		for i := 0; i+window <= len(token); i++ {
			part := token[i : i+window]
			if strings.Contains(before+after, part) {
				continue
			}
			if strings.Contains(out.String(), part) {
				t.Fatalf("token fragment %q survives in %q", part, out.String())
			}
		}
	})
}

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

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

func TestRedactCredentialSurfaces(t *testing.T) {
	tests := []struct{ name, input, secret string }{
		{"api key header any case", `X-API-KEY: k3y-v4lue-0001`, "k3y-v4lue-0001"},
		{"lower case api key header", `x-api-key=k3y-v4lue-0002`, "k3y-v4lue-0002"},
		{"apikey query", `GET /v1/decisions?apikey=k3y-v4lue-0003&limit=5`, "k3y-v4lue-0003"},
		{"api_key query", `GET /v1/sites?api_key=k3y-v4lue-0004`, "k3y-v4lue-0004"},
		{"bearer lower case", `authorization: bearer b34r3r-v4lue-0005`, "b34r3r-v4lue-0005"},
		{"basic authorization", `Authorization: Basic dXNlcjpwYXNzd29yZA==`, "dXNlcjpwYXNzd29yZA"},
		{"proxy authorization", `Proxy-Authorization: Basic cHJveHk6c2VjcmV0`, "cHJveHk6c2VjcmV0"},
		{"json authorization", `{"Authorization":"Basic dXNlcjpwYXNzd29yZA=="}`, "dXNlcjpwYXNzd29yZA"},
		{"multiple cookies", `Cookie: lang=en; sid=c00k13-v4lue-0006; theme=dark`, "c00k13-v4lue-0006"},
		{"set-cookie attributes", `Set-Cookie: unifises=c00k13-v4lue-0007; Path=/; HttpOnly`, "c00k13-v4lue-0007"},
		{"unifises cookie", `unifises=c00k13-v4lue-0008`, "c00k13-v4lue-0008"},
		{"token cookie", `TOKEN=eyJhbGciOiJIUzI1NiJ9.c00k13-0009`, "c00k13-0009"},
		{"csrf upper case", `X-CSRF-TOKEN: csrf-v4lue-0010`, "csrf-v4lue-0010"},
		{"password in escaped json body", `{"error":"login failed: {\"username\":\"admin\",\"password\":\"p4ss-v4lue-0011\"}"}`, "p4ss-v4lue-0011"},
		{"password with comma in escaped json", `{"body":"{\"password\":\"p4ss,v4lue-0012\"}"}`, "v4lue-0012"},
		{"password in json body", `{"username":"admin","password":"p4ss-v4lue-0013"}`, "p4ss-v4lue-0013"},
		{"lapi key header", `X-Api-Key: l4pi-v4lue-0014`, "l4pi-v4lue-0014"},
		{"lapi key field", `CROWDSEC_LAPI_KEY=l4pi-v4lue-0015`, "l4pi-v4lue-0015"},
		{"url userinfo", `Get "https://admin:p4ss-v4lue-0016@192.0.2.1/proxy/network": dial tcp`, "p4ss-v4lue-0016"},
		{"url userinfo username only", `dial https://tok3n-v4lue-0017@lapi.example:8080/v1`, "tok3n-v4lue-0017"},
		{"url userinfo in escaped json", `{"error":"Get \"http://u:p4ss-v4lue-0018@lapi:8080/v1/decisions\": EOF"}`, "p4ss-v4lue-0018"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redact(tt.input)
			if strings.Contains(got, tt.secret) {
				t.Errorf("secret %q not redacted: %q", tt.secret, got)
			}
			if !strings.Contains(got, "[REDACTED]") {
				t.Errorf("no redaction marker in %q", got)
			}
		})
	}
}

func TestRedactKeepsSurroundingContext(t *testing.T) {
	tests := []struct{ name, input, want string }{
		{"userinfo keeps host and path", `GET https://admin:pw@192.0.2.1:443/proxy/network?x=1`, `GET https://[REDACTED]@192.0.2.1:443/proxy/network?x=1`},
		{"at sign in path is not userinfo", `GET https://host.example/feed@v2/list`, `GET https://host.example/feed@v2/list`},
		{"at sign in query is not userinfo", `GET https://host.example/list?owner=a@b.example`, `GET https://host.example/list?owner=a@b.example`},
		{"basic word in prose", `falling back to basic auth for the proxy`, `falling back to basic auth for the proxy`},
		{"escaped json stays parsable", `{"error":"{\"password\":\"hunter2\",\"user\":\"a\"}"}`, `{"error":"{\"password\":\"[REDACTED]\",\"user\":\"a\"}"}`},
		{"bearer keeps scheme", `Authorization: Bearer abc.def`, `Authorization: Bearer [REDACTED]`},
		{"basic keeps scheme", `Authorization: Basic YWJj`, `Authorization: Basic [REDACTED]`},
		{"cookie stops at line end", "Cookie: a=1; b=2\nnext line", "Cookie: [REDACTED]\nnext line"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := redact(tt.input); got != tt.want {
				t.Errorf("redact(%q)\n got %q\nwant %q", tt.input, got, tt.want)
			}
		})
	}
}

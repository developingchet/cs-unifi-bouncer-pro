package logger

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSafeURL(t *testing.T) {
	tests := []struct {
		raw, want string
	}{
		{"https://feeds.example.com/list.txt", "https://feeds.example.com/list.txt"},
		{"https://feeds.example.com/list.txt?token=abc&x=1", "https://feeds.example.com/list.txt?<redacted>"},
		{"https://user:pass@feeds.example.com/list.txt#frag", "https://feeds.example.com/list.txt"},
		{"http://mock:8080/blocklist.txt?token=e2e", "http://mock:8080/blocklist.txt?<redacted>"},
		{"://bad", "<unparseable URL>"},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			if got := SafeURL(tt.raw); got != tt.want {
				t.Errorf("SafeURL(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestSafeHost(t *testing.T) {
	got := SafeHost("https://hooks.slack.com/services/T000/B000/secret")
	if got != "https://hooks.slack.com" {
		t.Fatalf("SafeHost = %q", got)
	}
}

func TestSafeURLError(t *testing.T) {
	raw := "http://127.0.0.1:1/list.txt?token=secret-token"
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Skip("port 1 unexpectedly accepted a connection")
	}
	if !strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("expected net/http to embed the URL, got %v", err)
	}
	safe := SafeURLError(err, SafeURL(raw))
	if strings.Contains(safe.Error(), "secret-token") {
		t.Fatalf("token leaked: %v", safe)
	}
	if errors.Unwrap(safe) == nil {
		t.Fatal("cause was dropped")
	}
}

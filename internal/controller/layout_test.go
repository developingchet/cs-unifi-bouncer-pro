package controller

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestDetectLayout(t *testing.T) {
	tests := []struct {
		name   string
		status int
		want   apiLayout
	}{
		{"UniFi OS console serves its UI", http.StatusOK, layoutUniFiOS},
		{"standalone redirects to /manage", http.StatusFound, layoutStandalone},
		{"unexpected status keeps UniFi OS", http.StatusNotFound, layoutUniFiOS},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tt.status == http.StatusFound {
					w.Header().Set("Location", "/manage")
				}
				w.WriteHeader(tt.status)
			}))
			defer srv.Close()
			client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			}}
			got, err := detectLayout(context.Background(), client, srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("layout = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestDetectLayoutUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	if _, err := detectLayout(context.Background(), &http.Client{Timeout: time.Second}, url); err == nil {
		t.Fatal("expected an error for an unreachable controller")
	}
}

// TestStandaloneClientPaths drives a client against a server shaped like a
// self-hosted Network Application: / redirects, login is /api/login, and the
// Network API has no /proxy/network prefix.
func TestStandaloneClientPaths(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "/manage", http.StatusFound)
		case "/api/login":
			http.SetCookie(w, &http.Cookie{Name: "unifises", Value: "session"})
			w.WriteHeader(http.StatusOK)
		case "/api/self", "/api/s/default/rest/firewallgroup":
			if _, err := r.Cookie("unifises"); err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	ctrl, err := NewClient(context.Background(), ClientConfig{
		BaseURL: srv.URL, Username: "admin", Password: "secret", Timeout: time.Second,
	}, zerolog.Nop())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer ctrl.Close()
	if err := ctrl.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if _, err := ctrl.ListFirewallGroups(context.Background(), "default"); err != nil {
		t.Fatalf("ListFirewallGroups: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	want := []string{"GET /", "POST /api/login", "GET /api/self", "GET /api/s/default/rest/firewallgroup"}
	if len(seen) != len(want) {
		t.Fatalf("requests = %v, want %v", seen, want)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("requests = %v, want %v", seen, want)
		}
	}
}

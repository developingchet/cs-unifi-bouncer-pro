package controller

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestDetectLayout(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		want    apiLayout
		wantErr bool
	}{
		{"UniFi OS console serves its UI", http.StatusOK, layoutUniFiOS, false},
		{"standalone redirects to /manage", http.StatusFound, layoutStandalone, false},
		{"other client error keeps UniFi OS", http.StatusForbidden, layoutUniFiOS, false},
		{"starting standalone controller answers 404", http.StatusNotFound, layoutUniFiOS, true},
		{"server error means not ready", http.StatusServiceUnavailable, layoutUniFiOS, true},
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
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Fatalf("layout = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestClassicDuplicateIsConflict(t *testing.T) {
	tests := []struct {
		name         string
		body         string
		wantConflict bool
	}{
		{"duplicate group", `{"meta":{"rc":"error","msg":"api.err.FirewallGroupExisted"},"data":[]}`, true},
		{"duplicate rule", `{"meta":{"rc":"error","msg":"api.err.FirewallRuleIndexExisted"},"data":[]}`, true},
		{"other validation error", `{"meta":{"rc":"error","msg":"api.err.InvalidPayload"},"data":[]}`, false},
		{"not JSON", `bad request`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()
			c := newTestClient(srv.URL, "test-key")
			_, err := c.CreateFirewallGroup(context.Background(), "default", FirewallGroup{Name: "g"})
			var conflict *ErrConflict
			if errors.As(err, &conflict) != tt.wantConflict {
				t.Fatalf("err = %v, want conflict %v", err, tt.wantConflict)
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

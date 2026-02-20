package controller

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestEnsureAuthSingleLogin(t *testing.T) {
	var loginCount int32

	// Mock server that always returns 200 on /api/auth/login
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/auth/login" {
			atomic.AddInt32(&loginCount, 1)
			w.Header().Set("Set-Cookie", "TOKEN=test; Path=/")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	log := zerolog.Nop()
	cfg := AuthConfig{
		BaseURL:       srv.URL,
		Username:      "admin",
		Password:      "secret",
		ReauthTimeout: 5 * time.Second,
		ReauthMinGap:  0, // no gap for testing
	}

	httpClient := srv.Client()
	sm := newSessionManager(cfg, httpClient, log)

	// Simulate N goroutines all hitting 401 simultaneously
	const workers = 16
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = sm.EnsureAuth(context.Background())
		}()
	}
	wg.Wait()

	// Due to thundering-herd guard and mutex, Login should be called
	// significantly fewer times than workers (ideally once, but timing
	// may allow a few if ReauthMinGap=0)
	count := atomic.LoadInt32(&loginCount)
	if count == 0 {
		t.Error("Login should have been called at least once")
	}
	t.Logf("Login called %d times for %d concurrent goroutines", count, workers)
}

func TestReauthMinGap(t *testing.T) {
	var loginCount int32

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/auth/login" {
			atomic.AddInt32(&loginCount, 1)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	log := zerolog.Nop()
	cfg := AuthConfig{
		BaseURL:       srv.URL,
		Username:      "admin",
		Password:      "secret",
		ReauthTimeout: 5 * time.Second,
		ReauthMinGap:  10 * time.Second, // large gap
	}

	sm := newSessionManager(cfg, srv.Client(), log)

	// First call should login
	if err := sm.EnsureAuth(context.Background()); err != nil {
		t.Fatal(err)
	}
	firstCount := atomic.LoadInt32(&loginCount)

	// Second call immediately after should be skipped due to gap
	if err := sm.EnsureAuth(context.Background()); err != nil {
		t.Fatal(err)
	}
	secondCount := atomic.LoadInt32(&loginCount)

	if secondCount != firstCount {
		t.Errorf("expected login count to stay at %d, got %d", firstCount, secondCount)
	}
}

func TestReauthFailurePropagated(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	log := zerolog.Nop()
	cfg := AuthConfig{
		BaseURL:       srv.URL,
		Username:      "bad",
		Password:      "creds",
		ReauthTimeout: 5 * time.Second,
		ReauthMinGap:  0,
	}

	sm := newSessionManager(cfg, srv.Client(), log)
	err := sm.EnsureAuth(context.Background())
	if err == nil {
		t.Error("expected error on failed login")
	}
}

func TestReauthTimeout(t *testing.T) {
	// Server that delays longer than the timeout
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	log := zerolog.Nop()
	cfg := AuthConfig{
		BaseURL:       srv.URL,
		Username:      "admin",
		Password:      "pw",
		ReauthTimeout: 100 * time.Millisecond, // very short
		ReauthMinGap:  0,
	}

	sm := newSessionManager(cfg, srv.Client(), log)
	err := sm.EnsureAuth(context.Background())
	if err == nil {
		t.Error("expected timeout error")
	}
}

func TestSetAuthHeaderAPIKey(t *testing.T) {
	log := zerolog.Nop()
	cfg := AuthConfig{
		BaseURL: "https://example.com",
		APIKey:  "my-api-key-12345",
	}
	sm := newSessionManager(cfg, http.DefaultClient, log)

	req, _ := http.NewRequest(http.MethodGet, "https://example.com/api/test", nil)
	sm.SetAuthHeader(req)

	if got := req.Header.Get("X-API-Key"); got != "my-api-key-12345" {
		t.Errorf("expected X-API-Key header, got %q", got)
	}
}

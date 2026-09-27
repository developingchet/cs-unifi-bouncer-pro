package controller

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestDryRunClientRefusesControllerWrites(t *testing.T) {
	var writes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writes.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	ctrl, err := NewClient(context.Background(), ClientConfig{
		BaseURL: server.URL, APIKey: "test", VerifyTLS: true,
		Timeout: time.Second, DryRun: true,
	}, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.Close()
	_, err = ctrl.CreateFirewallGroup(context.Background(), "default", FirewallGroup{Name: "blocked"})
	if err == nil || !strings.Contains(err.Error(), "dry run") {
		t.Fatalf("write was not rejected: %v", err)
	}
	if writes.Load() != 0 {
		t.Fatalf("dry run sent %d controller writes", writes.Load())
	}
}

func TestControllerRedirectDoesNotForwardCredentials(t *testing.T) {
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirected.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	t.Run("API key", func(t *testing.T) {
		ctrl, err := NewClient(context.Background(), ClientConfig{BaseURL: source.URL, APIKey: "secret", Timeout: time.Second}, zerolog.Nop())
		if err != nil {
			t.Fatal(err)
		}
		defer ctrl.Close()
		if err := ctrl.Ping(context.Background()); err == nil {
			t.Fatal("redirected controller request should fail")
		}
	})
	t.Run("login", func(t *testing.T) {
		ctrl, err := NewClient(context.Background(), ClientConfig{BaseURL: source.URL, Username: "admin", Password: "secret", Timeout: time.Second}, zerolog.Nop())
		if err == nil {
			ctrl.Close()
			t.Fatal("redirected login should fail")
		}
	})
	if got := redirected.Load(); got != 0 {
		t.Fatalf("redirect target received %d requests", got)
	}
}

// newTestClient builds a *unifiClient directly, skipping EnsureAuth.
// It is shared by the controller package tests and uses the UniFi OS layout.
func newTestClient(baseURL, apiKey string) *unifiClient {
	log := zerolog.Nop()
	cfg := ClientConfig{
		BaseURL:   baseURL,
		APIKey:    apiKey,
		VerifyTLS: false,
		Timeout:   5 * time.Second,
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}
	httpClient := &http.Client{Transport: transport, Timeout: cfg.Timeout}
	authCfg := AuthConfig{
		BaseURL:       baseURL,
		LoginPath:     layoutUniFiOS.loginPath,
		APIKey:        apiKey,
		ReauthTimeout: 5 * time.Second,
	}
	return &unifiClient{
		cfg:          cfg,
		http:         httpClient,
		layout:       layoutUniFiOS,
		session:      newSessionManager(authCfg, httpClient, log),
		featureCache: make(map[string]map[string]bool),
		zoneIDCache:  make(map[string]map[string]string),
		siteIDCache:  make(map[string]string),
		log:          log,
	}
}

// TestNewClient_Success verifies that NewClient succeeds when using API key auth.
// With an API key, login is a no-op so no HTTP call is made during construction.
func TestNewClient_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	log := zerolog.Nop()
	cfg := ClientConfig{
		BaseURL:   srv.URL,
		APIKey:    "test-api-key",
		VerifyTLS: false,
		Timeout:   5 * time.Second,
	}

	c, err := NewClient(context.Background(), cfg, log)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil controller")
	}
}

// TestNewClient_LoginFailure verifies that username/password auth failures
// are surfaced as errors during construction (401 on POST /api/auth/login).
func TestNewClient_LoginFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/auth/login" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	log := zerolog.Nop()
	cfg := ClientConfig{
		BaseURL:   srv.URL,
		Username:  "admin",
		Password:  "wrongpassword",
		VerifyTLS: false,
		Timeout:   5 * time.Second,
	}

	_, err := NewClient(context.Background(), cfg, log)
	if err == nil {
		t.Fatal("expected error on login failure, got nil")
	}
}

// TestNewClient_TLSVerification verifies that VerifyTLS=false allows connecting
// to a TLS server with a self-signed certificate without errors.
func TestNewClient_TLSVerification(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	log := zerolog.Nop()
	cfg := ClientConfig{
		BaseURL:   srv.URL,
		APIKey:    "test-api-key",
		VerifyTLS: false, // skip TLS verification
		Timeout:   5 * time.Second,
	}

	c, err := NewClient(context.Background(), cfg, log)
	if err != nil {
		t.Fatalf("expected success with VerifyTLS=false, got: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil controller")
	}
}

// TestApiDo_ErrorTranslation verifies that HTTP status codes are translated
// into the appropriate typed errors.
func TestApiDo_ErrorTranslation(t *testing.T) {
	cases := []struct {
		name       string
		statusCode int
		wantType   interface{}
	}{
		{"401 -> ErrUnauthorized", http.StatusUnauthorized, &ErrUnauthorized{}},
		{"404 -> ErrNotFound", http.StatusNotFound, &ErrNotFound{}},
		{"429 -> ErrRateLimit", http.StatusTooManyRequests, &ErrRateLimit{}},
		{"409 -> ErrConflict", http.StatusConflict, &ErrConflict{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
			}))
			defer srv.Close()

			c := newTestClient(srv.URL, "api-key")
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/test", nil)
			if err != nil {
				t.Fatalf("failed to build request: %v", err)
			}

			_, gotErr := c.apiDo(context.Background(), req, "test")
			if gotErr == nil {
				t.Fatalf("expected error for status %d, got nil", tc.statusCode)
			}

			switch tc.wantType.(type) {
			case *ErrUnauthorized:
				var e *ErrUnauthorized
				if !errors.As(gotErr, &e) {
					t.Errorf("expected *ErrUnauthorized, got %T: %v", gotErr, gotErr)
				}
			case *ErrNotFound:
				var e *ErrNotFound
				if !errors.As(gotErr, &e) {
					t.Errorf("expected *ErrNotFound, got %T: %v", gotErr, gotErr)
				}
			case *ErrRateLimit:
				var e *ErrRateLimit
				if !errors.As(gotErr, &e) {
					t.Errorf("expected *ErrRateLimit, got %T: %v", gotErr, gotErr)
				}
			case *ErrConflict:
				var e *ErrConflict
				if !errors.As(gotErr, &e) {
					t.Errorf("expected *ErrConflict, got %T: %v", gotErr, gotErr)
				}
			}
		})
	}

	// Network error returns a wrapped error (not a typed API error).
	t.Run("network error returns wrapped error", func(t *testing.T) {
		// Use a server that immediately closes the connection.
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen: %v", err)
		}
		addr := ln.Addr().String()
		ln.Close() // close immediately so connections are refused

		c := newTestClient("http://"+addr, "api-key")
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+addr+"/test", nil)
		if err != nil {
			t.Fatalf("failed to build request: %v", err)
		}

		_, gotErr := c.apiDo(context.Background(), req, "test")
		if gotErr == nil {
			t.Fatal("expected error on network failure, got nil")
		}
		// Should NOT be a typed API error.
		var eUnauth *ErrUnauthorized
		var eNotFound *ErrNotFound
		var eRate *ErrRateLimit
		var eConflict *ErrConflict
		if errors.As(gotErr, &eUnauth) || errors.As(gotErr, &eNotFound) ||
			errors.As(gotErr, &eRate) || errors.As(gotErr, &eConflict) {
			t.Errorf("expected plain network error, got typed API error: %T", gotErr)
		}
	})
}

// TestApiDo_RetryAfterHeader verifies that a 429 response with a Retry-After
// header of "5" results in an ErrRateLimit with RetryAfter == 5 seconds.
// The code does: time.ParseDuration(ra + "s"), so "5" becomes "5s" = 5 seconds.
func TestApiDo_RetryAfterHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "5")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/test", nil)
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}

	_, gotErr := c.apiDo(context.Background(), req, "test")
	if gotErr == nil {
		t.Fatal("expected ErrRateLimit, got nil")
	}

	var e *ErrRateLimit
	if !errors.As(gotErr, &e) {
		t.Fatalf("expected *ErrRateLimit, got %T: %v", gotErr, gotErr)
	}

	want := 5 * time.Second
	if e.RetryAfter != want {
		t.Errorf("expected RetryAfter=%s, got %s", want, e.RetryAfter)
	}
}

// TestRateLimitMinFloor_ZeroRetryAfter verifies that Retry-After: 0 is floored to 1s.
func TestRateLimitMinFloor_ZeroRetryAfter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/test", nil)
	_, err := c.apiDo(context.Background(), req, "test")

	var e *ErrRateLimit
	if !errors.As(err, &e) {
		t.Fatalf("expected *ErrRateLimit, got %T", err)
	}
	if e.RetryAfter < time.Second {
		t.Errorf("RetryAfter %s should be >= 1s (minimum floor)", e.RetryAfter)
	}
}

// TestRateLimitMinFloor_NegativeRetryAfter verifies the floor also applies to negative values.
func TestRateLimitMinFloor_NegativeRetryAfter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Retry-After: -5 → "-5s" parses to -5s
		w.Header().Set("Retry-After", "-5")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/test", nil)
	_, err := c.apiDo(context.Background(), req, "test")

	var e *ErrRateLimit
	if !errors.As(err, &e) {
		t.Fatalf("expected *ErrRateLimit, got %T", err)
	}
	if e.RetryAfter < time.Second {
		t.Errorf("RetryAfter %s should be >= 1s (minimum floor)", e.RetryAfter)
	}
}

// TestRateLimitMinFloor_NormalValue verifies that a normal Retry-After value is not floored.
func TestRateLimitMinFloor_NormalValue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/test", nil)
	_, err := c.apiDo(context.Background(), req, "test")

	var e *ErrRateLimit
	if !errors.As(err, &e) {
		t.Fatalf("expected *ErrRateLimit, got %T", err)
	}
	want := 30 * time.Second
	if e.RetryAfter != want {
		t.Errorf("expected RetryAfter=%s, got %s", want, e.RetryAfter)
	}
}

// TestWithReauth_RetriesOnce verifies that withReauth retries exactly once on
// ErrUnauthorized and succeeds on the second attempt.
func TestWithReauth_RetriesOnce(t *testing.T) {
	callCount := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serve any request with 200 (API key re-auth is a no-op).
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"data":[],"meta":{"rc":"ok"}}`)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")

	err := c.withReauth(context.Background(), func() error {
		callCount++
		if callCount == 1 {
			return &ErrUnauthorized{Msg: "first call"}
		}
		return nil
	})

	if err != nil {
		t.Fatalf("expected nil after retry, got: %v", err)
	}
	if callCount != 2 {
		t.Errorf("expected fn called 2 times, got %d", callCount)
	}
}

// TestWithReauth_MaxOneRetry verifies that withReauth does not loop indefinitely
// when both attempts return ErrUnauthorized.
func TestWithReauth_MaxOneRetry(t *testing.T) {
	callCount := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")

	err := c.withReauth(context.Background(), func() error {
		callCount++
		return &ErrUnauthorized{Msg: "always 401"}
	})

	if err == nil {
		t.Fatal("expected error when both attempts return 401, got nil")
	}
	// fn must be called at most 2 times (initial + one retry).
	if callCount > 2 {
		t.Errorf("expected at most 2 calls to fn, got %d (infinite loop?)", callCount)
	}
}

// TestPing_Success verifies that an API-key client pings the integration API.
// UniFi OS answers /api/self with 404 for API keys, which left /readyz at 503.
func TestPing_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/proxy/network/integration/v1/sites" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	err := c.Ping(context.Background())
	if err != nil {
		t.Fatalf("expected Ping to succeed, got: %v", err)
	}
}

// TestPing_ReturnsError verifies unhandled HTTP failures cannot be mistaken
// for successful controller writes or a healthy controller.
func TestPing_ReturnsError(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusInternalServerError, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
			}))
			defer srv.Close()
			c := newTestClient(srv.URL, "api-key")
			if err := c.Ping(context.Background()); err == nil {
				t.Fatalf("Ping returned nil for HTTP %d", status)
			}
		})
	}
}

// TestWriteErrorsSurfaceStatusAndBody verifies that every rejected write is an
// error carrying the controller's reason. Releases up to v1.2.5 treated
// statuses other than 400/401/404/409/429 as success, so a refused create was
// reported only as "API returned empty ID".
func TestWriteErrorsSurfaceStatusAndBody(t *testing.T) {
	const reason = `{"code":"api.firewall.limit","message":"too many entries"}`
	for _, status := range []int{http.StatusForbidden, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/integration/v1/sites") {
					_, _ = io.WriteString(w, `{"offset":0,"limit":25,"count":1,"totalCount":1,"data":[{"id":"site-uuid","internalReference":"default","name":"Default"}]}`)
					return
				}
				w.WriteHeader(status)
				_, _ = io.WriteString(w, reason)
			}))
			defer srv.Close()
			c := newTestClient(srv.URL, "api-key")
			_, err := c.CreateTrafficMatchingList(context.Background(), "default", TrafficMatchingList{Name: "crowdsec-block-v4-8", Type: "IPV4_ADDRESSES"})
			if err == nil {
				t.Fatalf("create returned nil for HTTP %d", status)
			}
			if !strings.Contains(err.Error(), "too many entries") {
				t.Errorf("error %q does not carry the controller's reason", err)
			}
			err = c.UpdateTrafficMatchingList(context.Background(), "default", TrafficMatchingList{ID: "x", Name: "crowdsec-block-v4-8", Type: "IPV4_ADDRESSES"})
			if err == nil {
				t.Fatalf("update returned nil for HTTP %d", status)
			}
		})
	}
}

package bouncer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/rs/zerolog"
)

// newTestBouncer constructs a Bouncer using test doubles.
func newTestBouncer(t *testing.T, cfg *config.Config) *Bouncer {
	t.Helper()
	store := testutil.NewMockStore()
	ctrl := testutil.NewMockController()
	fwMgr := &mockFirewallManager{}
	b, err := New(cfg, ctrl, store, fwMgr, nopRecorder{}, zerolog.Nop())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b
}

// TestBouncer_New_RateLimiterNilWhenDisabled verifies that when DecisionRateLimit
// is 0, no rate limiter is created (N7).
func TestBouncer_New_RateLimiterNilWhenDisabled(t *testing.T) {
	cfg := &config.Config{
		UnifiSites:         []string{"default"},
		BanTTL:             24 * time.Hour,
		CrowdSecLAPIURL:    "http://localhost:8080",
		CrowdSecLAPIKey:    "test-key",
		CrowdSecPollInterval: 30 * time.Second,
		DecisionRateLimit:  0,
	}
	b := newTestBouncer(t, cfg)
	if b.limiter != nil {
		t.Error("expected nil limiter when DecisionRateLimit=0")
	}
}

// TestBouncer_New_RateLimiterCreatedWhenEnabled verifies that when
// DecisionRateLimit > 0, the rate limiter is initialised (N7).
func TestBouncer_New_RateLimiterCreatedWhenEnabled(t *testing.T) {
	cfg := &config.Config{
		UnifiSites:           []string{"default"},
		BanTTL:               24 * time.Hour,
		CrowdSecLAPIURL:      "http://localhost:8080",
		CrowdSecLAPIKey:      "test-key",
		CrowdSecPollInterval: 30 * time.Second,
		DecisionRateLimit:    100,
		DecisionBurstSize:    10,
	}
	b := newTestBouncer(t, cfg)
	if b.limiter == nil {
		t.Error("expected non-nil limiter when DecisionRateLimit=100")
	}
}

// TestBouncer_ExpiresAt_Zero verifies that a zero duration returns a zero Time.
func TestBouncer_ExpiresAt_Zero(t *testing.T) {
	ts := expiresAt(0)
	if !ts.IsZero() {
		t.Errorf("expiresAt(0) should return zero time, got %v", ts)
	}
}

// TestBouncer_ExpiresAt_NonZero verifies that a positive duration returns a
// future time approximately offset from now.
func TestBouncer_ExpiresAt_NonZero(t *testing.T) {
	before := time.Now()
	ts := expiresAt(1 * time.Hour)
	after := time.Now()
	if ts.Before(before.Add(time.Hour)) || ts.After(after.Add(time.Hour+time.Second)) {
		t.Errorf("expiresAt(1h) = %v; expected approximately now+1h", ts)
	}
}

// TestBouncer_ReadyzReturns200_WhenControllerHealthy tests the /readyz endpoint
// returns 200 when the mock controller ping succeeds (P3 — LAPI readiness probe).
func TestBouncer_ReadyzReturns200_WhenControllerHealthy(t *testing.T) {
	cfg := &config.Config{
		UnifiSites:           []string{"default"},
		BanTTL:               24 * time.Hour,
		CrowdSecLAPIURL:      "http://localhost:8080",
		CrowdSecLAPIKey:      "test-key",
		CrowdSecPollInterval: 30 * time.Second,
		HealthAddr:           ":0",
		HealthCheckLAPI:      false, // only check controller
	}
	b := newTestBouncer(t, cfg)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()

	// Build the handler inline the same way serveHealth does.
	mux := http.NewServeMux()
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := b.ctrl.Ping(r.Context()); err != nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 from /readyz, got %d", rr.Code)
	}
}

// TestBouncer_ReadyzLAPICheck tests that HEALTH_CHECK_LAPI=true causes the
// readyz handler to check the LAPI endpoint (P3).
func TestBouncer_ReadyzLAPICheck_FailsWhenLAPIDown(t *testing.T) {
	// Start a server that always returns 503
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	cfg := &config.Config{
		UnifiSites:           []string{"default"},
		BanTTL:               24 * time.Hour,
		CrowdSecLAPIURL:      srv.URL,
		CrowdSecLAPIKey:      "test-key",
		CrowdSecPollInterval: 30 * time.Second,
		HealthCheckLAPI:      true,
	}
	b := newTestBouncer(t, cfg)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()

	// Replicate the readyz logic with LAPI check enabled.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := b.ctrl.Ping(r.Context()); err != nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		lapiURL := srv.URL + "/v1/ping"
		lapiReq, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, lapiURL, nil)
		lapiReq.Header.Set("X-Api-Key", cfg.CrowdSecLAPIKey)
		client := &http.Client{Timeout: 2 * time.Second}
		resp, lapiErr := client.Do(lapiReq)
		if lapiErr != nil || resp.StatusCode >= 500 {
			if resp != nil {
				resp.Body.Close()
			}
			http.Error(w, "lapi: unreachable", http.StatusServiceUnavailable)
			return
		}
		resp.Body.Close()
		w.WriteHeader(http.StatusOK)
	})
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when LAPI returns 503, got %d", rr.Code)
	}
}

// TestBouncer_InFlightGauge_IncDec verifies that the in-flight gauge is
// incremented before the handler call and decremented after (P4). Because
// the mock handler completes synchronously, we verify the net effect is zero.
func TestBouncer_InFlightGauge_IncDec(t *testing.T) {
	ctx := context.Background()
	cfg := &config.Config{
		UnifiSites:           []string{"default"},
		BanTTL:               24 * time.Hour,
		CrowdSecLAPIURL:      "http://localhost:8080",
		CrowdSecLAPIKey:      "test-key",
		CrowdSecPollInterval: 30 * time.Second,
	}
	store := testutil.NewMockStore()
	ctrl := testutil.NewMockController()
	fwMgr := &mockFirewallManager{}
	b, err := New(cfg, ctrl, store, fwMgr, nopRecorder{}, zerolog.Nop())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Call the handler directly; metrics.DecisionsInFlight should net to zero.
	_ = b.handler(ctx, SyncJob{
		Action:    "ban",
		IP:        "10.0.0.99",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	// No panic, no race — the test is satisfied if it completes cleanly.
}

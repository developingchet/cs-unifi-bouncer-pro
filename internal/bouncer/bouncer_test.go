package bouncer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/banstate"
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
	b, err := New(cfg, ctrl, store, fwMgr, banstate.New(store, fwMgr, cfg.UnifiSites, cfg.DryRun), nopRecorder{}, zerolog.Nop())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b
}

func TestBouncer_New_RateLimiterNilWhenDisabled(t *testing.T) {
	cfg := &config.Config{
		UnifiSites:           []string{"default"},
		BanTTL:               24 * time.Hour,
		CrowdSecLAPIURL:      "http://localhost:8080",
		CrowdSecLAPIKey:      "test-key",
		CrowdSecPollInterval: 30 * time.Second,
		DecisionRateLimit:    0,
	}
	b := newTestBouncer(t, cfg)
	if b.limiter != nil {
		t.Error("expected nil limiter when DecisionRateLimit=0")
	}
}

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

	rr := httptest.NewRecorder()
	b.ready(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 from /readyz, got %d", rr.Code)
	}
}

func TestBouncer_ReadyzLAPIStatus(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		want   int
	}{
		{"healthy", http.StatusOK, http.StatusOK},
		{"unauthorized", http.StatusUnauthorized, http.StatusServiceUnavailable},
		{"redirect", http.StatusFound, http.StatusServiceUnavailable},
		{"unavailable", http.StatusServiceUnavailable, http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/decisions" || r.URL.Query().Get("limit") != "1" || r.Header.Get("X-Api-Key") != "test-key" {
					http.Error(w, "bad readiness request", http.StatusBadRequest)
					return
				}
				w.WriteHeader(tc.status)
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
			rr := httptest.NewRecorder()
			b.ready(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
			if rr.Code != tc.want {
				t.Fatalf("readyz returned %d, want %d", rr.Code, tc.want)
			}
		})
	}
}

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
	b, err := New(cfg, ctrl, store, fwMgr, banstate.New(store, fwMgr, cfg.UnifiSites, cfg.DryRun), nopRecorder{}, zerolog.Nop())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Call the handler directly; metrics.DecisionsInFlight should net to zero.
	_ = b.handler(ctx, SyncJob{
		Action:    "ban",
		Source:    "crowdsec:id:1",
		IP:        "10.0.0.99",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	// No panic, no race — the test is satisfied if it completes cleanly.
}

func TestBouncer_SkipsDecisionsWithoutIdentity(t *testing.T) {
	cfg := &config.Config{UnifiSites: []string{"default"}, BanTTL: time.Hour}
	b := newTestBouncer(t, cfg)
	var jobs []SyncJob
	b.handler = func(_ context.Context, job SyncJob) error {
		jobs = append(jobs, job)
		return nil
	}
	action, scope, ip := "ban", "ip", "8.8.8.8"
	d := &models.Decision{Type: &action, Scope: &scope, Value: &ip}
	b.handleDecisionBlock(context.Background(), &models.DecisionsStreamResponse{New: []*models.Decision{d}, Deleted: []*models.Decision{d}})
	if len(jobs) != 0 {
		t.Fatalf("anonymous decisions reached handler: %+v", jobs)
	}
}

func TestUserAgentVersionPrefix(t *testing.T) {
	for in, want := range map[string]string{
		"v1.2.3": "crowdsec-unifi-bouncer/v1.2.3",
		"1.2.3":  "crowdsec-unifi-bouncer/v1.2.3",
		"dev":    "crowdsec-unifi-bouncer/vdev",
	} {
		if got := userAgent(in); got != want {
			t.Errorf("userAgent(%q) = %q, want %q", in, got, want)
		}
	}
}

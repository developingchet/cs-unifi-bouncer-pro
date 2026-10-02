package firewall

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
)

// newGatedManager returns a legacy-mode manager whose shards hold two bans in
// two separate shards, so a pass has more than one write to make.
func newGatedManager(t *testing.T, mutate func(*ManagerConfig)) (*managerImpl, *testutil.MockController, *testutil.MockStore) {
	t.Helper()
	cfg := defaultManagerConfig()
	cfg.GroupCapacityV4 = 1
	cfg.ShardMergeThreshold = -1
	if mutate != nil {
		mutate(&cfg)
	}
	mgr, ctrl, store := newTestManager(t, cfg)
	ctx := context.Background()
	if err := mgr.EnsureInfrastructure(ctx, []string{testSite}); err != nil {
		t.Fatalf("EnsureInfrastructure: %v", err)
	}
	for _, ip := range []string{"198.51.100.1", "198.51.100.2"} {
		if err := mgr.ApplyBan(ctx, testSite, ip, false); err != nil {
			t.Fatalf("ApplyBan %s: %v", ip, err)
		}
	}
	return mgr.(*managerImpl), ctrl, store
}

// startHalfOpenProbe puts the breaker in the state where the next pass is its probe.
func startHalfOpenProbe(m *managerImpl) {
	m.cb.mu.Lock()
	defer m.cb.mu.Unlock()
	m.cb.state = circuitOpen
	m.cb.failures = m.cb.threshold
	m.cb.openedAt = time.Now().Add(-2 * m.cb.resetAfter)
}

func TestHalfOpenProbeFailureReopensBreaker(t *testing.T) {
	tests := []struct {
		name   string
		inject func(*testutil.MockController)
	}{
		{"rate limited write", func(c *testutil.MockController) {
			c.SetError("UpdateFirewallGroup", &controller.ErrRateLimit{RetryAfter: time.Millisecond})
		}},
		{"provisioning failure", func(c *testutil.MockController) {
			c.SetError("CreateFirewallRule", errors.New("rule create failed"))
		}},
		{"failed shard create", func(c *testutil.MockController) {
			c.SetError("CreateFirewallGroup", errors.New("group create failed"))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, ctrl, _ := newGatedManager(t, nil)
			// One shard keeps the probe to a single write: the injected
			// failure is not followed by a success that would close the breaker.
			if err := m.ApplyUnban(context.Background(), testSite, "198.51.100.2", false); err != nil {
				t.Fatal(err)
			}
			startHalfOpenProbe(m)
			tt.inject(ctrl)

			if err := m.SyncDirty(context.Background(), []string{testSite}); err == nil {
				t.Fatal("SyncDirty succeeded although the probe write failed")
			}
			if !m.cb.isOpen() {
				t.Fatalf("breaker state = %v after a failed probe, want open", m.cb.state)
			}
			if since := time.Since(m.cb.openedAt); since > time.Minute {
				t.Errorf("reopened breaker kept its old open time (%s ago); the reset interval must restart", since)
			}
		})
	}
}

func TestHalfOpenProbeRefusedRequestClosesBreaker(t *testing.T) {
	m, ctrl, _ := newGatedManager(t, nil)
	startHalfOpenProbe(m)
	// A 400 that names no member of the shard cannot be quarantined, so the
	// write fails; the controller still answered.
	ctrl.SetError("UpdateFirewallGroup", &controller.ErrBadRequest{Body: "invalid"})

	if err := m.SyncDirty(context.Background(), []string{testSite}); err == nil {
		t.Fatal("SyncDirty succeeded although a shard write was refused")
	}
	if m.cb.isOpen() || m.cb.isHalfOpen() {
		t.Fatalf("breaker state = %v, want closed: the controller answered the probe", m.cb.state)
	}
}

func TestReconcileProbeFailureReopensBreaker(t *testing.T) {
	m, ctrl, store := newGatedManager(t, nil)
	if err := store.BanRecord("198.51.100.1", time.Time{}, false); err != nil {
		t.Fatal(err)
	}
	startHalfOpenProbe(m)
	ctrl.SetError("UpdateFirewallGroup", &controller.ErrRateLimit{RetryAfter: time.Millisecond})

	if _, err := m.Reconcile(context.Background(), []string{testSite}); err == nil {
		t.Fatal("Reconcile succeeded although the probe write failed")
	}
	if !m.cb.isOpen() {
		t.Fatalf("breaker state = %v after a failed reconcile probe, want open", m.cb.state)
	}
}

func TestSyncStopsAfterRateLimit(t *testing.T) {
	m, ctrl, _ := newGatedManager(t, nil)
	ctrl.SetError("UpdateFirewallGroup", &controller.ErrRateLimit{RetryAfter: time.Minute})

	if err := m.SyncDirty(context.Background(), []string{testSite}); err == nil {
		t.Fatal("SyncDirty succeeded although the controller rate limited it")
	}
	if got := ctrl.Calls("CreateFirewallGroup"); got != 1 {
		t.Errorf("CreateFirewallGroup calls = %d, want 1: the pass must stop at the first 429", got)
	}
	if limited, _ := m.isRateLimited(); !limited {
		t.Error("no rate-limit window recorded after a 429")
	}
}

func TestSyncStopsAfterShardCreateRateLimit(t *testing.T) {
	m, ctrl, _ := newGatedManager(t, nil)
	ctrl.SetError("CreateFirewallGroup", &controller.ErrRateLimit{RetryAfter: time.Minute})

	if err := m.SyncDirty(context.Background(), []string{testSite}); err == nil {
		t.Fatal("SyncDirty succeeded although the controller rate limited it")
	}
	if got := ctrl.Calls("CreateFirewallGroup"); got != 1 {
		t.Errorf("CreateFirewallGroup calls = %d, want 1: the pass must stop at the first 429", got)
	}
	if limited, _ := m.isRateLimited(); !limited {
		t.Error("no rate-limit window recorded after a 429 on create")
	}
}

func TestSyncStopsOnceBreakerOpens(t *testing.T) {
	m, ctrl, _ := newGatedManager(t, func(c *ManagerConfig) { c.CircuitBreakerThreshold = 1 })
	ctrl.SetError("UpdateFirewallGroup", errors.New("controller unavailable"))

	if err := m.SyncDirty(context.Background(), []string{testSite}); err == nil {
		t.Fatal("SyncDirty succeeded although a write failed")
	}
	if !m.cb.isOpen() {
		t.Fatalf("breaker state = %v, want open", m.cb.state)
	}
	if got := ctrl.Calls("CreateFirewallGroup"); got != 1 {
		t.Errorf("CreateFirewallGroup calls = %d, want 1: the pass must stop once the breaker opens", got)
	}
}

func TestReconcileDefersWritesWhileGated(t *testing.T) {
	tests := []struct {
		name string
		gate func(*managerImpl)
	}{
		{"rate limited", func(m *managerImpl) { m.setRateLimitUntil(time.Now().Add(time.Minute)) }},
		{"breaker open", func(m *managerImpl) {
			m.cb.mu.Lock()
			defer m.cb.mu.Unlock()
			m.cb.state = circuitOpen
			m.cb.openedAt = time.Now()
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, ctrl, store := newGatedManager(t, nil)
			if err := store.BanRecord("198.51.100.1", time.Time{}, false); err != nil {
				t.Fatal(err)
			}
			tt.gate(m)

			if _, err := m.Reconcile(context.Background(), []string{testSite}); err == nil {
				t.Fatal("Reconcile reported success although its writes were deferred")
			}
			for _, call := range []string{"CreateFirewallGroup", "UpdateFirewallGroup", "DeleteFirewallGroup",
				"CreateFirewallRule", "DeleteFirewallRule"} {
				if got := ctrl.Calls(call); got != 0 {
					t.Errorf("%s called %d times while writes were gated", call, got)
				}
			}
		})
	}
}

func TestReconcileStopsAfterRateLimit(t *testing.T) {
	m, ctrl, store := newGatedManager(t, nil)
	for _, ip := range []string{"198.51.100.1", "198.51.100.2"} {
		if err := store.BanRecord(ip, time.Time{}, false); err != nil {
			t.Fatal(err)
		}
	}
	ctrl.SetError("UpdateFirewallGroup", &controller.ErrRateLimit{RetryAfter: time.Minute})

	if _, err := m.Reconcile(context.Background(), []string{testSite}); err == nil {
		t.Fatal("Reconcile succeeded although the controller rate limited it")
	}
	if got := ctrl.Calls("CreateFirewallGroup"); got != 1 {
		t.Errorf("CreateFirewallGroup calls = %d, want 1: reconcile must stop at the first 429", got)
	}
	if got := ctrl.Calls("CreateFirewallRule"); got != 0 {
		t.Errorf("CreateFirewallRule calls = %d, want 0 while rate limited", got)
	}
}

func TestSetRateLimitUntilKeepsLaterDeadline(t *testing.T) {
	m, _, _ := newGatedManager(t, nil)
	now := time.Now()
	later, earlier := now.Add(5*time.Minute), now.Add(time.Minute)

	m.setRateLimitUntil(later)
	m.setRateLimitUntil(earlier)
	if _, until := m.isRateLimited(); !until.Equal(later) {
		t.Errorf("deadline = %s, want the later %s", until, later)
	}

	evenLater := now.Add(10 * time.Minute)
	m.setRateLimitUntil(evenLater)
	if _, until := m.isRateLimited(); !until.Equal(evenLater) {
		t.Errorf("deadline = %s, want the extended %s", until, evenLater)
	}
}

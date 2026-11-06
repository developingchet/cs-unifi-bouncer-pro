package firewall

import (
	"context"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	promtest "github.com/prometheus/client_golang/prometheus/testutil"
)

// Each site reports the addresses in its own shards: one site whose ban
// failed to apply does not show the other site's count.
func TestActiveBansFollowEachSitesShards(t *testing.T) {
	ctx := context.Background()
	metrics.ActiveBans.Reset()
	mgr, _, store := newTestManager(t, defaultManagerConfig())
	sites := []string{"site-a", "site-b"}
	if err := mgr.EnsureInfrastructure(ctx, sites); err != nil {
		t.Fatal(err)
	}
	m := mgr.(*managerImpl)
	for _, ip := range []string{"198.51.100.1", "198.51.100.2"} {
		if err := testutil.PutBan(store, ip, time.Time{}, false); err != nil {
			t.Fatal(err)
		}
		if err := m.ApplyBan(ctx, "site-a", ip, false); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.ApplyBan(ctx, "site-b", "198.51.100.1", false); err != nil {
		t.Fatal(err)
	}
	store.ResetCalls()

	if err := m.SyncDirty(ctx, sites); err != nil {
		t.Fatal(err)
	}
	for site, want := range map[string]float64{"site-a": 2, "site-b": 1} {
		if got := promtest.ToFloat64(metrics.ActiveBans.WithLabelValues("v4", site)); got != want {
			t.Errorf("active_bans{site=%q} = %v, want %v", site, got, want)
		}
	}
	if got := store.Calls("BanList"); got != 0 {
		t.Errorf("SyncDirty read the ban list %d times, want 0", got)
	}
}

// A reconcile of several sites reads the ban list once and confirms its
// differences with one key-only read per family, not one read per address.
func TestReconcileReadsBanDatabaseOnce(t *testing.T) {
	ctx := context.Background()
	mgr, _, store := newTestManager(t, defaultManagerConfig())
	sites := []string{"site-a", "site-b", "site-c"}
	if err := mgr.EnsureInfrastructure(ctx, sites); err != nil {
		t.Fatal(err)
	}
	m := mgr.(*managerImpl)
	banned := []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"}
	for _, ip := range banned {
		if err := testutil.PutBan(store, ip, time.Time{}, false); err != nil {
			t.Fatal(err)
		}
	}
	// site-a misses every ban and holds a stale address; site-b matches.
	if _, err := m.v4Mgrs["site-a"].Add(ctx, "203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	for _, ip := range banned {
		if _, err := m.v4Mgrs["site-b"].Add(ctx, ip); err != nil {
			t.Fatal(err)
		}
	}
	store.ResetCalls()

	result, err := m.Reconcile(ctx, sites)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.Added < 6 || result.Removed < 1 {
		t.Errorf("added, removed = %d, %d; want at least 6 (site-a and site-c) and 1", result.Added, result.Removed)
	}
	for method, want := range map[string]int{"BanList": 1, "BanExists": 0, "BanKeys": 2} {
		if got := store.Calls(method); got != want {
			t.Errorf("%s calls = %d, want %d", method, got, want)
		}
	}
	for _, site := range []string{"site-a", "site-c"} {
		sm := m.v4Mgrs[site]
		if sm.Len() != len(banned) || sm.Contains("203.0.113.9") {
			t.Errorf("%s holds %v after reconcile, want %v", site, sm.AllMembers(), banned)
		}
	}
}

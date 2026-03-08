package bouncer

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/firewall"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/rs/zerolog"
)

func newJanitorTestStore(t *testing.T) storage.Store {
	t.Helper()
	dir := t.TempDir()
	s, err := storage.NewBboltStore(dir, zerolog.Nop(), 0)
	if err != nil {
		t.Fatalf("NewBboltStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// nopFWManager satisfies firewall.Manager with no-op implementations for janitor tests.
type nopFWManager struct{}

func (nopFWManager) ApplyBan(_ context.Context, _, _ string, _ bool) error                              { return nil }
func (nopFWManager) ApplyBanWithZones(_ context.Context, _, _ string, _ bool, _ []config.ZonePair) error { return nil }
func (nopFWManager) ApplyUnban(_ context.Context, _, _ string, _ bool) error                            { return nil }
func (nopFWManager) Reconcile(_ context.Context, _ []string) (*firewall.ReconcileResult, error) {
	return &firewall.ReconcileResult{}, nil
}
func (nopFWManager) EnsureInfrastructure(_ context.Context, _ []string) error { return nil }
func (nopFWManager) SyncDirty(_ context.Context, _ []string) error             { return nil }
func (nopFWManager) Drain(_ context.Context, _ []string) error                 { return nil }
func (nopFWManager) ZoneManager() *firewall.ZoneManager                        { return nil }

func newTestJanitor(store storage.Store, interval time.Duration) *Janitor {
	return NewJanitor(store, nopFWManager{}, []string{"default"}, interval, zerolog.Nop())
}

func TestJanitor_PrunesExpiredBans(t *testing.T) {
	store := newJanitorTestStore(t)

	// Record a ban with past expiry
	past := time.Now().Add(-time.Hour)
	if err := store.BanRecord("1.2.3.4", past, false); err != nil {
		t.Fatal(err)
	}
	// Also record a fresh ban
	if err := store.BanRecord("5.6.7.8", time.Now().Add(time.Hour), false); err != nil {
		t.Fatal(err)
	}

	j := newTestJanitor(store, 100*time.Millisecond)
	j.tick(context.Background())

	// Expired ban should be gone
	exists, _ := store.BanExists("1.2.3.4")
	if exists {
		t.Error("expired ban should have been pruned")
	}
	// Fresh ban should remain
	exists, _ = store.BanExists("5.6.7.8")
	if !exists {
		t.Error("fresh ban should not be pruned")
	}
}

func TestJanitor_KeepsFreshBans(t *testing.T) {
	store := newJanitorTestStore(t)

	// Record a fresh ban
	if err := store.BanRecord("9.9.9.9", time.Now().Add(24*time.Hour), false); err != nil {
		t.Fatal(err)
	}

	j := newTestJanitor(store, 100*time.Millisecond)
	j.tick(context.Background())

	exists, _ := store.BanExists("9.9.9.9")
	if !exists {
		t.Error("fresh ban should not be pruned")
	}
}

func TestJanitor_UpdatesDBSizeMetric(t *testing.T) {
	store := newJanitorTestStore(t)

	j := newTestJanitor(store, 100*time.Millisecond)
	// tick() should not panic even if Prometheus metrics aren't registered
	// (they register on first use). Just verify no error/panic.
	j.tick(context.Background())
}

// errFWManager is a test firewall manager that fails ApplyUnban for a specific IP/site combo.
type errFWManager struct {
	nopFWManager
	failIP   string
	failSite string // empty = fail for all sites
}

func (e *errFWManager) ApplyUnban(_ context.Context, site, ip string, _ bool) error {
	if ip == e.failIP && (e.failSite == "" || site == e.failSite) {
		return errors.New("simulated unban failure")
	}
	return nil
}

func TestJanitor_SkipsPruneOnUnbanFailure(t *testing.T) {
	store := newJanitorTestStore(t)
	past := time.Now().Add(-time.Hour)

	// IP that will fail to unban
	if err := store.BanRecord("1.1.1.1", past, false); err != nil {
		t.Fatal(err)
	}
	// IP that will succeed
	if err := store.BanRecord("2.2.2.2", past, false); err != nil {
		t.Fatal(err)
	}

	fwMgr := &errFWManager{failIP: "1.1.1.1"}
	j := NewJanitor(store, fwMgr, []string{"default"}, 100*time.Millisecond, zerolog.Nop())
	j.tick(context.Background())

	// 1.1.1.1 should still be in bbolt (unban failed)
	exists, _ := store.BanExists("1.1.1.1")
	if !exists {
		t.Error("1.1.1.1 should remain in bbolt after failed unban")
	}
	// 2.2.2.2 should be pruned (unban succeeded)
	exists, _ = store.BanExists("2.2.2.2")
	if exists {
		t.Error("2.2.2.2 should have been pruned after successful unban")
	}
}

func TestJanitor_AllSitesFailKeepsIP(t *testing.T) {
	store := newJanitorTestStore(t)
	past := time.Now().Add(-time.Hour)
	if err := store.BanRecord("3.3.3.3", past, false); err != nil {
		t.Fatal(err)
	}

	fwMgr := &errFWManager{failIP: "3.3.3.3"} // fail for all sites
	j := NewJanitor(store, fwMgr, []string{"site-a", "site-b"}, 100*time.Millisecond, zerolog.Nop())
	j.tick(context.Background())

	exists, _ := store.BanExists("3.3.3.3")
	if !exists {
		t.Error("IP should remain in bbolt when all sites fail unban")
	}
}

func TestJanitor_PartialSiteFailKeepsIP(t *testing.T) {
	store := newJanitorTestStore(t)
	past := time.Now().Add(-time.Hour)
	if err := store.BanRecord("4.4.4.4", past, false); err != nil {
		t.Fatal(err)
	}

	// Only site-a fails
	fwMgr := &errFWManager{failIP: "4.4.4.4", failSite: "site-a"}
	j := NewJanitor(store, fwMgr, []string{"site-a", "site-b"}, 100*time.Millisecond, zerolog.Nop())
	j.tick(context.Background())

	// IP should still be in bbolt since one site failed
	exists, _ := store.BanExists("4.4.4.4")
	if !exists {
		t.Error("IP should remain in bbolt when any site fails unban")
	}
}

func TestJanitor_TickImmediatelyOnStart(t *testing.T) {
	store := newJanitorTestStore(t)

	// Record an expired ban
	if err := store.BanRecord("3.3.3.3", time.Now().Add(-time.Hour), false); err != nil {
		t.Fatal(err)
	}

	// Use a long ticker interval so the timer doesn't fire during the test
	j := newTestJanitor(store, 10*time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- j.Run(ctx)
	}()

	// Wait for context to expire
	<-ctx.Done()
	<-done

	// The first tick should have run immediately on start, pruning the expired ban
	exists, _ := store.BanExists("3.3.3.3")
	if exists {
		t.Error("expired ban should have been pruned on first immediate tick")
	}
}

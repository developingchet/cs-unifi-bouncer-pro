package firewall

import (
	"context"
	"testing"
	"time"
)

// TestDiffFamilyConfirmsChangesAgainstBanDatabase covers decisions applied
// while a reconcile runs: its desired set is a snapshot, so a ban recorded
// after it must survive and a ban lifted after it must not come back.
func TestDiffFamilyConfirmsChangesAgainstBanDatabase(t *testing.T) {
	ctx := context.Background()
	mgr, _, store := newTestManager(t, defaultManagerConfig())
	if err := mgr.EnsureInfrastructure(ctx, []string{testSite}); err != nil {
		t.Fatalf("EnsureInfrastructure: %v", err)
	}
	m := mgr.(*managerImpl)
	sm := m.v4Mgrs[testSite]

	const (
		kept    = "198.51.100.1" // in the snapshot and on the shard
		lifted  = "198.51.100.2" // in the snapshot, unbanned since
		fresh   = "198.51.100.3" // banned since the snapshot, already on the shard
		stale   = "198.51.100.4" // on the shard, banned by nobody
		pending = "198.51.100.5" // in the snapshot and in the database, not on the shard
	)
	for _, ip := range []string{kept, fresh, pending} {
		if err := store.BanRecord(ip, time.Time{}, false); err != nil {
			t.Fatal(err)
		}
	}
	for _, ip := range []string{kept, fresh, stale} {
		if _, _, err := sm.Add(ctx, ip); err != nil {
			t.Fatal(err)
		}
	}
	snapshot := map[string]struct{}{kept: {}, lifted: {}, pending: {}}

	added, removed, errs := m.diffFamily(ctx, sm, snapshot)
	if len(errs) != 0 {
		t.Fatalf("diffFamily errors: %v", errs)
	}
	if added != 1 || removed != 1 {
		t.Errorf("added, removed = %d, %d; want 1, 1", added, removed)
	}
	for ip, want := range map[string]bool{kept: true, lifted: false, fresh: true, stale: false, pending: true} {
		if got := sm.Contains(ip); got != want {
			t.Errorf("shard contains %s = %v, want %v", ip, got, want)
		}
	}
}

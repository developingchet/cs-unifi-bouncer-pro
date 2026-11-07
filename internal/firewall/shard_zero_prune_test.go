package firewall

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/rs/zerolog"
)

func TestEmptiedShardZeroIsPrunedAndCreatedAgain(t *testing.T) {
	ctx := context.Background()
	cfg := defaultManagerConfig()
	cfg.ShardMergeThreshold = -1
	ctrl := testutil.NewMockController()
	store := testutil.NewMockStore()
	mgr := NewManager(cfg, ctrl, store, managerTestNamer(t), zerolog.Nop()).(*managerImpl)
	if err := mgr.EnsureInfrastructure(ctx, []string{testSite}); err != nil {
		t.Fatal(err)
	}
	counts := func() (groups, rules int) {
		t.Helper()
		g, err := ctrl.ListFirewallGroups(ctx, testSite)
		if err != nil {
			t.Fatal(err)
		}
		r, err := ctrl.ListFirewallRules(ctx, testSite)
		if err != nil {
			t.Fatal(err)
		}
		return len(g), len(r)
	}

	const first, second = "198.51.100.1", "198.51.100.2"
	if err := testutil.PutBan(store, first, time.Time{}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Reconcile(ctx, []string{testSite}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if g, r := counts(); g != 1 || r != 1 {
		t.Fatalf("after the first ban: %d groups, %d rules; want 1 each", g, r)
	}

	// The only ban expires: the reconcile empties shard 0 and prunes it.
	if err := store.BanDelete(first); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := mgr.Reconcile(ctx, []string{testSite}); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
	}
	if g, r := counts(); g != 0 || r != 0 {
		t.Fatalf("after the last unban: %d groups, %d rules; want none", g, r)
	}
	if rec, err := getCachedPolicy(store, testSite, "crowdsec-drop-v4-0"); err != nil || rec != nil {
		t.Fatalf("record of the pruned rule kept: %+v, %v", rec, err)
	}

	// The next ban creates shard 0 again, with its rule.
	if err := testutil.PutBan(store, second, time.Time{}, false); err != nil {
		t.Fatal(err)
	}
	if err := mgr.ApplyBan(ctx, testSite, second, false); err != nil {
		t.Fatal(err)
	}
	if err := mgr.SyncDirty(ctx, []string{testSite}); err != nil {
		t.Fatalf("SyncDirty: %v", err)
	}
	if _, err := mgr.Reconcile(ctx, []string{testSite}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	groups, err := ctrl.ListFirewallGroups(ctx, testSite)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0].Name != "crowdsec-block-v4-0" || !slices.Contains(groups[0].GroupMembers, second) {
		t.Fatalf("groups after the new ban = %+v, want crowdsec-block-v4-0 holding %s", groups, second)
	}
	if _, r := counts(); r != 1 {
		t.Errorf("rules after the new ban = %d, want 1", r)
	}
}

package firewall

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/rs/zerolog"
)

// pruneHookController runs a hook just before the controller deletes a rule
// or a group, so a test can apply a ban while a tail shard is being pruned.
type pruneHookController struct {
	*testutil.MockController
	beforeDeleteRule  func()
	beforeDeleteGroup func()
}

func (c *pruneHookController) DeleteFirewallRule(ctx context.Context, site, id string) error {
	if c.beforeDeleteRule != nil {
		c.beforeDeleteRule()
	}
	return c.MockController.DeleteFirewallRule(ctx, site, id)
}

func (c *pruneHookController) DeleteFirewallGroup(ctx context.Context, site, id string) error {
	if c.beforeDeleteGroup != nil {
		c.beforeDeleteGroup()
	}
	return c.MockController.DeleteFirewallGroup(ctx, site, id)
}

// pruneFixture is a legacy-mode manager with two single-capacity shards, the
// second of which becomes empty on the next reconcile and is pruned.
type pruneFixture struct {
	ctrl *pruneHookController
	mgr  *managerImpl
	sm   *ShardManager
}

func newPruneFixture(t *testing.T) *pruneFixture {
	t.Helper()
	ctx := context.Background()
	cfg := defaultManagerConfig()
	cfg.GroupCapacityV4 = 1
	cfg.ShardMergeThreshold = -1
	ctrl := &pruneHookController{MockController: testutil.NewMockController()}
	store := testutil.NewMockStore()
	mgr := NewManager(cfg, ctrl, store, managerTestNamer(t), zerolog.Nop()).(*managerImpl)
	if err := mgr.EnsureInfrastructure(ctx, []string{testSite}); err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"198.51.100.1", "198.51.100.2"} {
		if err := store.BanRecord(ip, time.Time{}, false); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := mgr.Reconcile(ctx, []string{testSite}); err != nil {
		t.Fatalf("initial Reconcile: %v", err)
	}
	sm := mgr.v4Mgrs[testSite]
	if got := len(sm.GroupRefs()); got != 2 {
		t.Fatalf("active shards = %d, want 2", got)
	}
	// Reconcile fills the shards in map order, so lift whichever ban sits in the tail.
	if err := store.BanDelete(sm.fam.Shards[1].IPs.Members()[0]); err != nil {
		t.Fatal(err)
	}
	return &pruneFixture{ctrl: ctrl, mgr: mgr, sm: sm}
}

// banDuringPrune records a ban and applies it to the shards the way a
// decision does while the reconcile is deleting the tail shard.
func (f *pruneFixture) banDuringPrune(t *testing.T, ip string) {
	t.Helper()
	store := f.mgr.store
	if err := store.BanRecord(ip, time.Time{}, false); err != nil {
		t.Error(err)
	}
	if err := f.mgr.ApplyBan(context.Background(), testSite, ip, false); err != nil {
		t.Error(err)
	}
}

func (f *pruneFixture) groupMembers(t *testing.T) []string {
	t.Helper()
	groups, err := f.ctrl.ListFirewallGroups(context.Background(), testSite)
	if err != nil {
		t.Fatal(err)
	}
	var members []string
	for _, g := range groups {
		members = append(members, g.GroupMembers...)
	}
	return members
}

func TestBanAppliedWhileTailShardIsPrunedIsKept(t *testing.T) {
	const late = "198.51.100.3"
	tests := []struct {
		name string
		hook func(*pruneFixture) // installs the hook that applies the ban
	}{
		{"before its rule is deleted", func(f *pruneFixture) {
			f.ctrl.beforeDeleteRule = func() { f.banDuringPrune(t, late) }
		}},
		{"before its group is deleted", func(f *pruneFixture) {
			f.ctrl.beforeDeleteGroup = func() { f.banDuringPrune(t, late) }
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			f := newPruneFixture(t)
			tt.hook(f)

			if _, err := f.mgr.Reconcile(ctx, []string{testSite}); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			if !f.sm.Contains(late) {
				t.Fatalf("ban %s applied during the prune is no longer tracked by any shard", late)
			}

			// The next syncs write it to the controller and give its shard a rule.
			if err := f.mgr.SyncDirty(ctx, []string{testSite}); err != nil {
				t.Fatalf("SyncDirty: %v", err)
			}
			if _, err := f.mgr.Reconcile(ctx, []string{testSite}); err != nil {
				t.Fatalf("second Reconcile: %v", err)
			}
			if members := f.groupMembers(t); !slices.Contains(members, late) {
				t.Errorf("controller groups hold %v, want %s among them", members, late)
			}
			rules, err := f.ctrl.ListFirewallRules(ctx, testSite)
			if err != nil {
				t.Fatal(err)
			}
			if groups := len(f.sm.GroupRefs()); len(rules) != groups {
				t.Errorf("%d rules for %d active shards, want one each", len(rules), groups)
			}
		})
	}
}

func TestRemoveTailRequeuesMembersAddedBeforeRemoval(t *testing.T) {
	ctx := context.Background()
	ctrl := testutil.NewMockController()
	sm := NewShardManager(testSite, false, 1, testNamer(t), ctrl, testutil.NewMockStore(), zerolog.Nop(), 0, false, "legacy")
	for _, ip := range []string{"198.51.100.1", "198.51.100.2"} {
		if err := sm.AddIP(ctx, ip); err != nil {
			t.Fatal(err)
		}
	}
	if err := sm.FlushDirty(ctx); err != nil {
		t.Fatal(err)
	}
	sm.RemoveIP("198.51.100.2")
	if _, _, ok := sm.PrunableTail(); !ok {
		t.Fatal("tail shard is not prunable")
	}
	// A ban lands in the tail between the prunable check and the removal.
	if err := sm.AddIP(ctx, "198.51.100.3"); err != nil {
		t.Fatal(err)
	}

	if err := sm.RemoveTail(); err != nil {
		t.Fatal(err)
	}
	if !sm.Contains("198.51.100.3") || !sm.Contains("198.51.100.1") {
		t.Fatalf("members after removal = %v, want both bans kept", sm.AllMembers())
	}
	if refs := sm.GroupRefs(); len(refs) != 1 {
		t.Errorf("active shards = %+v, want the first only; the re-queued ban waits in a new shard", refs)
	}
	if err := sm.FlushDirty(ctx); err != nil {
		t.Fatal(err)
	}
	var created []controller.FirewallGroup
	created, _ = ctrl.ListFirewallGroups(ctx, testSite)
	var all []string
	for _, g := range created {
		all = append(all, g.GroupMembers...)
	}
	if !slices.Contains(all, "198.51.100.3") {
		t.Errorf("controller groups hold %v, want the re-queued ban", all)
	}
}

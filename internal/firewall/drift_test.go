package firewall

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
)

// TestReconcile_RepairsOutOfBandEdits verifies that reconcile rewrites a shard
// whose members were changed on the controller even though the bouncer's own
// state did not change.
func TestReconcile_RepairsOutOfBandEdits(t *testing.T) {
	tests := []struct {
		name        string
		remote      []string // members after the out-of-band edit
		wantAdded   int
		wantRemoved int
	}{
		{name: "members removed", remote: []string{"198.51.100.1"}, wantAdded: 1},
		{name: "group emptied", remote: nil, wantAdded: 2},
		{name: "member added", remote: []string{"198.51.100.1", "198.51.100.2", "198.51.100.99"}, wantRemoved: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			mgr, ctrl, store := newTestManager(t, defaultManagerConfig())
			if err := mgr.EnsureInfrastructure(ctx, []string{testSite}); err != nil {
				t.Fatalf("EnsureInfrastructure: %v", err)
			}
			for _, ip := range []string{"198.51.100.1", "198.51.100.2"} {
				if err := store.BanRecord(ip, time.Time{}, false); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := mgr.Reconcile(ctx, []string{testSite}); err != nil {
				t.Fatalf("first reconcile: %v", err)
			}

			group := v4Group(t, ctrl)
			group.GroupMembers = tt.remote
			ctrl.SetGroups(testSite, []controller.FirewallGroup{group})
			writes := ctrl.Calls("UpdateFirewallGroup")

			result, err := mgr.Reconcile(ctx, []string{testSite})
			if err != nil {
				t.Fatalf("repair reconcile: %v", err)
			}
			if result.Added != tt.wantAdded || result.Removed != tt.wantRemoved {
				t.Errorf("added/removed = %d/%d, want %d/%d", result.Added, result.Removed, tt.wantAdded, tt.wantRemoved)
			}
			if got := ctrl.Calls("UpdateFirewallGroup"); got != writes+1 {
				t.Errorf("UpdateFirewallGroup calls = %d, want %d", got, writes+1)
			}
			members := stripPlaceholders(v4Group(t, ctrl).GroupMembers)
			sort.Strings(members)
			if len(members) != 2 || members[0] != "198.51.100.1" || members[1] != "198.51.100.2" {
				t.Errorf("controller members after repair = %v", members)
			}

			// Once repaired, a further reconcile finds nothing to do.
			writes = ctrl.Calls("UpdateFirewallGroup")
			result, err = mgr.Reconcile(ctx, []string{testSite})
			if err != nil {
				t.Fatalf("steady reconcile: %v", err)
			}
			if result.Added != 0 || result.Removed != 0 || ctrl.Calls("UpdateFirewallGroup") != writes {
				t.Errorf("steady state: added=%d removed=%d extra writes=%d",
					result.Added, result.Removed, ctrl.Calls("UpdateFirewallGroup")-writes)
			}
		})
	}
}

func v4Group(t *testing.T, ctrl controller.Controller) controller.FirewallGroup {
	t.Helper()
	groups, err := ctrl.ListFirewallGroups(context.Background(), testSite)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range groups {
		if g.Name == "crowdsec-block-v4-0" {
			return g
		}
	}
	t.Fatalf("crowdsec-block-v4-0 not found in %+v", groups)
	return controller.FirewallGroup{}
}

// TestSyncShard_PutNotFound_Unconfirmed covers a 404 that a listing does not
// confirm: a restarting controller answers 404 for everything, and a group
// recreated elsewhere has a new ID.
func TestSyncShard_PutNotFound_Unconfirmed(t *testing.T) {
	const shardName, shardID = "crowdsec-block-v4-0", "shard-id-1"
	tests := []struct {
		name       string
		listed     []controller.FirewallGroup
		listErr    error
		wantErr    bool
		wantID     string
		wantActive bool
	}{
		{name: "group still listed: transient", wantErr: true, wantID: shardID, wantActive: true,
			listed: []controller.FirewallGroup{{ID: shardID, Name: shardName, GroupType: "address-group"}}},
		{name: "listing fails: transient", listErr: errors.New("controller starting"), wantErr: true, wantID: shardID, wantActive: true,
			listed: []controller.FirewallGroup{{ID: shardID, Name: shardName, GroupType: "address-group"}}},
		{name: "recreated with a new ID: adopted", wantID: "shard-id-2", wantActive: true,
			listed: []controller.FirewallGroup{{ID: "shard-id-2", Name: shardName, GroupType: "address-group"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			ctrl := testutil.NewMockController()
			store := testutil.NewMockStore()
			ctrl.SetGroups(testSite, []controller.FirewallGroup{
				{ID: shardID, Name: shardName, GroupType: "address-group", GroupMembers: []string{"198.51.100.1"}},
			})
			sm := newV4ShardManager(t, 100, ctrl, store)
			if err := sm.EnsureShards(ctx); err != nil {
				t.Fatalf("EnsureShards: %v", err)
			}
			if _, _, err := sm.Add(ctx, "198.51.100.2"); err != nil {
				t.Fatalf("Add: %v", err)
			}

			ctrl.SetGroups(testSite, tt.listed)
			ctrl.SetError("UpdateFirewallGroup", &controller.ErrNotFound{URL: "/api/groups/" + shardID})
			if tt.listErr != nil {
				ctrl.SetError("ListFirewallGroups", tt.listErr)
			}

			err := sm.syncAllFamilies(ctx)
			if (err != nil) != tt.wantErr {
				t.Fatalf("syncAllFamilies err = %v, wantErr %v", err, tt.wantErr)
			}
			sm.mu.RLock()
			shard := sm.families["v4"].Shards[0]
			gotID, gotState := shard.ID, shard.State
			sm.mu.RUnlock()
			if gotID != tt.wantID || (gotState == ShardStateActive) != tt.wantActive {
				t.Errorf("shard = id %q state %v, want id %q active %v", gotID, gotState, tt.wantID, tt.wantActive)
			}
			if !shard.IPs.IsDirty() {
				t.Error("shard must stay dirty so the next sync writes its members")
			}
		})
	}
}

func TestDiffMembers(t *testing.T) {
	tests := []struct {
		name           string
		want, have     []string
		missing, extra int
	}{
		{name: "equal", want: []string{"a", "b"}, have: []string{"b", "a"}},
		{name: "missing", want: []string{"a", "b"}, have: []string{"a"}, missing: 1},
		{name: "extra", want: []string{"a"}, have: []string{"a", "c"}, extra: 1},
		{name: "both", want: []string{"a", "b"}, have: []string{"c"}, missing: 2, extra: 1},
		{name: "leftover placeholder ignored", want: []string{"a"}, have: []string{"a", TMLPlaceholderV4}},
		{name: "banned placeholder address present", want: []string{TMLPlaceholderV4}, have: []string{TMLPlaceholderV4}},
		{name: "banned placeholder address missing", want: []string{TMLPlaceholderV4, "a"}, have: []string{"a"}, missing: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, e := diffMembers(tt.want, tt.have)
			if m != tt.missing || e != tt.extra {
				t.Errorf("diffMembers = %d/%d, want %d/%d", m, e, tt.missing, tt.extra)
			}
		})
	}
}

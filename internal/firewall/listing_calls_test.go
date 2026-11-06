package firewall

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
)

// listingCalls is how often each listing endpoint was called.
type listingCalls struct {
	tmls, policies, groups, rules int
}

func countListings(ctrl *testutil.MockController) listingCalls {
	return listingCalls{
		tmls:     ctrl.Calls("ListTrafficMatchingLists"),
		policies: ctrl.Calls("ListZonePolicies"),
		groups:   ctrl.Calls("ListFirewallGroups"),
		rules:    ctrl.Calls("ListFirewallRules"),
	}
}

func recordBans(t *testing.T, store *testutil.MockStore, v4, v6 string) {
	t.Helper()
	if err := testutil.PutBan(store, v4, time.Time{}, false); err != nil {
		t.Fatal(err)
	}
	if err := testutil.PutBan(store, v6, time.Time{}, true); err != nil {
		t.Fatal(err)
	}
}

// newZoneListingScenario sets up a zone-mode site with one shard per family,
// a port-filtered zone pair and a filter list left by a removed pair.
func newZoneListingScenario(t *testing.T) (Manager, *testutil.MockController, *testutil.MockStore) {
	t.Helper()
	cfg := defaultManagerConfig()
	cfg.FirewallMode = "zone"
	cfg.EnableIPv6 = true
	cfg.ZoneCfg.ZonePairs = []config.ZonePair{{Src: "wan", Dst: "lan", DstPorts: []int{22}}}
	mgr, ctrl, store := newTestManager(t, cfg)
	ctrl.SetTMLs(testSite, []controller.TrafficMatchingList{
		{ID: "tml-v4", Name: "crowdsec-block-v4-0", Type: "IPV4_ADDRESSES",
			Items: []controller.TrafficMatchingListItem{{Type: "IP_ADDRESS", Value: "198.51.100.1"}}},
		{ID: "tml-v6", Name: "crowdsec-block-v6-0", Type: "IPV6_ADDRESSES",
			Items: []controller.TrafficMatchingListItem{{Type: "IP_ADDRESS", Value: "2001:db8::10"}}},
		{ID: "tml-old-filter", Name: "crowdsec-ports-dst-dmz-lan", Type: "PORTS",
			Items: []controller.TrafficMatchingListItem{{Type: "PORT_NUMBER", Value: "80"}}},
	})
	recordBans(t, store, "198.51.100.1", "2001:db8::10")
	return mgr, ctrl, store
}

// TestZoneEnsureInfrastructureListsEachCollectionOnce checks that a startup
// load and repair of a zone-mode site fetches its traffic matching lists and
// zone policies once, although shard loading, the filter lists, the policy
// repair and the orphan sweeps all read them.
func TestZoneEnsureInfrastructureListsEachCollectionOnce(t *testing.T) {
	mgr, ctrl, _ := newZoneListingScenario(t)
	if err := mgr.EnsureInfrastructure(context.Background(), []string{testSite}); err != nil {
		t.Fatalf("EnsureInfrastructure: %v", err)
	}
	got := countListings(ctrl)
	t.Logf("EnsureInfrastructure listings: %+v", got)
	if got.tmls != 1 || got.policies != 1 {
		t.Errorf("listings = %+v, want one of traffic matching lists and one of policies", got)
	}
	if ctrl.Calls("CreateZonePolicy") != 2 || ctrl.Calls("DeleteTrafficMatchingList") != 1 {
		t.Errorf("created %d policies and deleted %d lists, want 2 and 1",
			ctrl.Calls("CreateZonePolicy"), ctrl.Calls("DeleteTrafficMatchingList"))
	}
}

// TestZoneReconcileListsEachCollectionOnce checks that a reconcile of a
// zone-mode site fetches its traffic matching lists once for both address
// families' drift checks and the orphan sweep, and its policies once.
func TestZoneReconcileListsEachCollectionOnce(t *testing.T) {
	mgr, ctrl, _ := newZoneListingScenario(t)
	ctx := context.Background()
	if err := mgr.EnsureInfrastructure(ctx, []string{testSite}); err != nil {
		t.Fatalf("EnsureInfrastructure: %v", err)
	}
	ctrl.ResetCalls()
	if _, err := mgr.Reconcile(ctx, []string{testSite}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	got := countListings(ctrl)
	t.Logf("Reconcile listings: %+v", got)
	if got.tmls != 1 || got.policies != 1 {
		t.Errorf("listings = %+v, want one of traffic matching lists and one of policies", got)
	}
}

// TestZoneReconcileCreatingAShardListsOnce checks that a reconcile that
// creates a shard and its block policy still fetches each listing once, and
// that the new shard ends up with its policy.
func TestZoneReconcileCreatingAShardListsOnce(t *testing.T) {
	mgr, ctrl, store := newZoneListingScenario(t)
	ctx := context.Background()
	if err := mgr.EnsureInfrastructure(ctx, []string{testSite}); err != nil {
		t.Fatalf("EnsureInfrastructure: %v", err)
	}
	// Capacity is 5: five more bans fill shard 0 and open shard 1.
	for i := 2; i <= 6; i++ {
		if err := testutil.PutBan(store, fmt.Sprintf("198.51.100.%d", i), time.Time{}, false); err != nil {
			t.Fatal(err)
		}
	}
	ctrl.ResetCalls()
	if _, err := mgr.Reconcile(ctx, []string{testSite}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if got := ctrl.Calls("CreateTrafficMatchingList"); got != 1 {
		t.Fatalf("CreateTrafficMatchingList = %d, want 1", got)
	}
	got := countListings(ctrl)
	t.Logf("Reconcile listings with a new shard: %+v", got)
	if got.tmls != 1 || got.policies != 1 {
		t.Errorf("listings = %+v, want one of traffic matching lists and one of policies", got)
	}
	policies, err := ctrl.ListZonePolicies(ctx, testSite)
	if err != nil {
		t.Fatal(err)
	}
	names := make(map[string]bool, len(policies))
	for _, p := range policies {
		names[p.Name] = true
	}
	for _, want := range []string{"crowdsec-policy-wan-lan-v4-0", "crowdsec-policy-wan-lan-v4-1", "crowdsec-policy-wan-lan-v6-0"} {
		if !names[want] {
			t.Errorf("policy %s missing after reconcile; have %v", want, names)
		}
	}
}

// newLegacyListingScenario sets up a legacy-mode site with one group per
// family and their drop rules.
func newLegacyListingScenario(t *testing.T) (Manager, *testutil.MockController) {
	t.Helper()
	cfg := defaultManagerConfig()
	cfg.EnableIPv6 = true
	mgr, ctrl, store := newTestManager(t, cfg)
	ctrl.SetGroups(testSite, []controller.FirewallGroup{
		{ID: "group-v4", Name: "crowdsec-block-v4-0", GroupType: "address-group", GroupMembers: []string{"198.51.100.1"}},
		{ID: "group-v6", Name: "crowdsec-block-v6-0", GroupType: "ipv6-address-group", GroupMembers: []string{"2001:db8::10"}},
	})
	recordBans(t, store, "198.51.100.1", "2001:db8::10")
	return mgr, ctrl
}

// TestLegacyListingsPerPass checks that startup and reconcile of a legacy
// site fetch its firewall groups and rules once each.
func TestLegacyListingsPerPass(t *testing.T) {
	mgr, ctrl := newLegacyListingScenario(t)
	ctx := context.Background()
	if err := mgr.EnsureInfrastructure(ctx, []string{testSite}); err != nil {
		t.Fatalf("EnsureInfrastructure: %v", err)
	}
	got := countListings(ctrl)
	t.Logf("EnsureInfrastructure listings: %+v", got)
	if got.groups != 1 || got.rules != 1 {
		t.Errorf("EnsureInfrastructure listings = %+v, want one of groups and one of rules", got)
	}

	ctrl.ResetCalls()
	if _, err := mgr.Reconcile(ctx, []string{testSite}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	got = countListings(ctrl)
	t.Logf("Reconcile listings: %+v", got)
	if got.groups != 1 || got.rules != 1 {
		t.Errorf("Reconcile listings = %+v, want one of groups and one of rules", got)
	}
}

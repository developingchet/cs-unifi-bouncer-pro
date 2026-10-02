package firewall

import (
	"context"
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
)

// zoneDrainFixture seeds a zone-mode controller with everything a bouncer
// with port filters leaves behind, plus objects that belong to someone else.
func zoneDrainFixture(t *testing.T, dryRun bool) (Manager, *stagedPolicyFixture) {
	t.Helper()
	f := newStagedPolicyFixture(t)
	cfg := defaultManagerConfig()
	cfg.FirewallMode = "zone"
	cfg.DryRun = dryRun
	cfg.ZoneCfg.ZonePairs = []config.ZonePair{{Src: "wan", Dst: "lan"}}
	mgr := NewManager(cfg, f.ctrl, f.zm.store, managerTestNamer(t), f.zm.log)
	foreign := controller.ZonePolicy{ID: "foreign", Name: "user-policy", Action: "BLOCK", Description: "someone else",
		DstPortTMLID: "shared-ports"}
	f.ctrl.SetPolicies(testSite, []controller.ZonePolicy{f.block, f.stagedCopy(), foreign})
	f.ctrl.SetTMLs(testSite, []controller.TrafficMatchingList{
		{ID: "shared-ports", Name: filterDstPortsPrefix + "wan-lan-abc", Type: "PORTS"},
		{ID: "unused-ports", Name: filterSrcPortsPrefix + "wan-lan", Type: "PORTS"},
		{ID: "unused-ips", Name: filterDstIPsV4Prefix + "wan-lan", Type: "IPV4_ADDRESSES"},
		{ID: "user-list", Name: "my-own-list", Type: "PORTS"},
	})
	if err := mgr.PrepareDrain(context.Background(), []string{testSite}); err != nil {
		t.Fatal(err)
	}
	return mgr, f
}

func TestDrainRemovesStagedPoliciesAndFilterLists(t *testing.T) {
	ctx := context.Background()
	mgr, f := zoneDrainFixture(t, false)

	if err := mgr.Drain(ctx, []string{testSite}); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	policies, err := f.ctrl.ListZonePolicies(ctx, testSite)
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 1 || policies[0].ID != "foreign" {
		t.Errorf("policies after drain = %+v, want only the foreign policy", policies)
	}
	tmls, err := f.ctrl.ListTrafficMatchingLists(ctx, testSite)
	if err != nil {
		t.Fatal(err)
	}
	var left []string
	for _, tml := range tmls {
		left = append(left, tml.ID)
	}
	want := map[string]bool{"shared-ports": true, "user-list": true}
	if len(left) != len(want) {
		t.Fatalf("lists after drain = %v, want %v kept", left, want)
	}
	for _, id := range left {
		if !want[id] {
			t.Errorf("list %s survived the drain", id)
		}
	}
}

func TestDrainDryRunLeavesStagedPoliciesAndFilterLists(t *testing.T) {
	ctx := context.Background()
	mgr, f := zoneDrainFixture(t, true)

	if err := mgr.Drain(ctx, []string{testSite}); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	for _, call := range []string{"DeleteZonePolicy", "DeleteTrafficMatchingList"} {
		if got := f.ctrl.Calls(call); got != 0 {
			t.Errorf("%s called %d times in a dry run", call, got)
		}
	}
}

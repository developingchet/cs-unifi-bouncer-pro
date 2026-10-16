package firewall

import (
	"context"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
)

// migratedSite sets up a zone-mode site the way it looks after the controller
// moved it to the zone-based firewall: the shard list survived under its name,
// the bouncer's legacy rule became a zone policy with the rule's name, and the
// ban database still records the rule.
func migratedSite(t *testing.T, extra ...controller.ZonePolicy) (Manager, *testutil.MockController, *testutil.MockStore) {
	t.Helper()
	cfg := defaultManagerConfig()
	cfg.FirewallMode = "zone"
	cfg.ZoneCfg.ZonePairs = []config.ZonePair{{Src: "wan", Dst: "lan"}}
	mgr, ctrl, store := newTestManager(t, cfg)
	ctrl.SetTMLs(testSite, []controller.TrafficMatchingList{{
		ID: "tml-0", Name: "crowdsec-block-v4-0", Type: "IPV4_ADDRESSES",
		Items: []controller.TrafficMatchingListItem{{Type: "IP_ADDRESS", Value: "203.0.113.7"}},
	}})
	if err := store.BanRecord("203.0.113.7", time.Time{}, false); err != nil {
		t.Fatal(err)
	}
	if err := store.SetPolicy(cacheKey(testSite, "crowdsec-drop-v4-0"),
		storage.PolicyRecord{UnifiID: "rule-0", Site: testSite, Mode: "legacy"}); err != nil {
		t.Fatal(err)
	}
	converted := controller.ZonePolicy{
		ID: "converted-0", Name: "crowdsec-drop-v4-0", Enabled: true, Action: "BLOCK",
		SrcZone: "External", DstZone: "Internal", IPVersion: "IPV4",
		TrafficMatchingListIDs: []string{"tml-0"},
	}
	ctrl.SetPolicies(testSite, append([]controller.ZonePolicy{converted}, extra...))
	return mgr, ctrl, store
}

func policyNames(t *testing.T, ctrl *testutil.MockController) map[string]bool {
	t.Helper()
	policies, err := ctrl.ListZonePolicies(context.Background(), testSite)
	if err != nil {
		t.Fatal(err)
	}
	names := make(map[string]bool, len(policies))
	for _, p := range policies {
		names[p.Name] = true
	}
	return names
}

func TestRepairRetiresConvertedLegacyRule(t *testing.T) {
	mgr, ctrl, store := migratedSite(t)
	if err := mgr.EnsureInfrastructure(context.Background(), []string{testSite}); err != nil {
		t.Fatalf("EnsureInfrastructure: %v", err)
	}
	names := policyNames(t, ctrl)
	if names["crowdsec-drop-v4-0"] {
		t.Error("converted legacy rule kept after the block policy was created")
	}
	if !names["crowdsec-policy-wan-lan-v4-0"] {
		t.Errorf("block policy missing: %v", names)
	}
	if rec, err := getCachedPolicy(store, testSite, "crowdsec-drop-v4-0"); err != nil || rec != nil {
		t.Errorf("legacy rule record = %+v, %v; want it removed", rec, err)
	}
}

func TestRepairKeepsConvertedRuleUntilCovered(t *testing.T) {
	mgr, ctrl, store := migratedSite(t)
	ctrl.SetError("CreateZonePolicy", errTest("HTTP 500"))
	if err := mgr.EnsureInfrastructure(context.Background(), []string{testSite}); err != nil {
		t.Fatalf("EnsureInfrastructure: %v", err)
	}
	if !policyNames(t, ctrl)["crowdsec-drop-v4-0"] {
		t.Error("converted legacy rule deleted while its list had no block policy")
	}
	if rec, err := getCachedPolicy(store, testSite, "crowdsec-drop-v4-0"); err != nil || rec == nil {
		t.Errorf("legacy rule record = %+v, %v; want it kept for the next attempt", rec, err)
	}

	// The next reconcile creates the block policy and retires the rule.
	if _, err := mgr.Reconcile(context.Background(), []string{testSite}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	names := policyNames(t, ctrl)
	if names["crowdsec-drop-v4-0"] || !names["crowdsec-policy-wan-lan-v4-0"] {
		t.Errorf("policies after reconcile = %v; want the block policy and no converted rule", names)
	}
	if rec, err := getCachedPolicy(store, testSite, "crowdsec-drop-v4-0"); err != nil || rec != nil {
		t.Errorf("legacy rule record = %+v, %v; want it removed", rec, err)
	}
	lists := ctrl.Calls("ListZonePolicies")
	if err := mgr.(*managerImpl).retryConvertedRules(context.Background(), testSite); err != nil {
		t.Fatal(err)
	}
	if ctrl.Calls("ListZonePolicies") != lists {
		t.Error("retirement retried after nothing was left to retire")
	}
}

func TestPruneDeletesKeptConvertedRule(t *testing.T) {
	mgr, ctrl, _ := migratedSite(t)
	ctrl.SetError("CreateZonePolicy", errTest("HTTP 500"))
	ctx := context.Background()
	if err := mgr.EnsureInfrastructure(ctx, []string{testSite}); err != nil {
		t.Fatalf("EnsureInfrastructure: %v", err)
	}
	impl := mgr.(*managerImpl)
	lists := ctrl.Calls("ListZonePolicies")
	if err := impl.deleteConvertedRulesForList(ctx, "other-site", "tml-0"); err != nil {
		t.Fatal(err)
	}
	if ctrl.Calls("ListZonePolicies") != lists {
		t.Error("a site with no kept converted rules listed its policies")
	}
	if err := impl.deleteConvertedRulesForList(ctx, testSite, "tml-0"); err != nil {
		t.Fatalf("deleteConvertedRulesForList: %v", err)
	}
	if policyNames(t, ctrl)["crowdsec-drop-v4-0"] {
		t.Error("converted legacy rule kept although its list is being deleted")
	}
}

func TestRepairLeavesForeignPolicies(t *testing.T) {
	foreign := []controller.ZonePolicy{
		{ID: "user-block", Name: "block-scanners", Enabled: true, Action: "BLOCK", TrafficMatchingListIDs: []string{"tml-0"}},
		{ID: "allow-named-like-rule", Name: "crowdsec-drop-v4-9", Enabled: true, Action: "ALLOW", TrafficMatchingListIDs: []string{"tml-0"}},
		{ID: "other-list", Name: "crowdsec-drop-v4-5", Enabled: true, Action: "BLOCK", TrafficMatchingListIDs: []string{"user-list"}},
	}
	mgr, ctrl, _ := migratedSite(t, foreign...)
	if err := mgr.EnsureInfrastructure(context.Background(), []string{testSite}); err != nil {
		t.Fatalf("EnsureInfrastructure: %v", err)
	}
	names := policyNames(t, ctrl)
	for _, p := range foreign {
		if !names[p.Name] {
			t.Errorf("policy %q deleted; it does not block a managed list as a converted rule", p.Name)
		}
	}
	if names["crowdsec-drop-v4-0"] {
		t.Error("converted legacy rule kept")
	}
}

func TestRepairRetiresConvertedRejectRuleByPrefix(t *testing.T) {
	// A rule from a wiped database is still recognised by the rule prefix.
	mgr, ctrl, store := migratedSite(t, controller.ZonePolicy{
		ID: "converted-reject", Name: "crowdsec-drop-v4-0-reject", Enabled: true, Action: "REJECT",
		TrafficMatchingListIDs: []string{"tml-0"},
	})
	if err := store.DeletePolicy(cacheKey(testSite, "crowdsec-drop-v4-0")); err != nil {
		t.Fatal(err)
	}
	if err := mgr.EnsureInfrastructure(context.Background(), []string{testSite}); err != nil {
		t.Fatalf("EnsureInfrastructure: %v", err)
	}
	names := policyNames(t, ctrl)
	if names["crowdsec-drop-v4-0"] || names["crowdsec-drop-v4-0-reject"] {
		t.Errorf("converted rules kept: %v", names)
	}
}

func TestDrainDeletesConvertedLegacyRule(t *testing.T) {
	mgr, ctrl, store := migratedSite(t)
	ctx := context.Background()
	if err := mgr.PrepareDrain(ctx, []string{testSite}); err != nil {
		t.Fatalf("PrepareDrain: %v", err)
	}
	if err := mgr.Drain(ctx, []string{testSite}); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if names := policyNames(t, ctrl); names["crowdsec-drop-v4-0"] {
		t.Errorf("converted legacy rule left after drain: %v", names)
	}
	tmls, err := ctrl.ListTrafficMatchingLists(ctx, testSite)
	if err != nil || len(tmls) != 0 {
		t.Errorf("lists after drain = %+v, %v; want none", tmls, err)
	}
	policies, err := store.ListPolicies()
	if err != nil || len(policies) != 0 {
		t.Errorf("policy records after drain = %v, %v; want none", policies, err)
	}
}

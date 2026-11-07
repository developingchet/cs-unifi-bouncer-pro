package firewall

import (
	"context"
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/rs/zerolog"
)

// ruleIDs returns the IDs of the site's rules on ctrl.
func ruleIDs(t *testing.T, ctrl controller.Controller) map[string]bool {
	t.Helper()
	rules, err := ctrl.ListFirewallRules(context.Background(), testSite)
	if err != nil {
		t.Fatal(err)
	}
	ids := make(map[string]bool, len(rules))
	for _, r := range rules {
		ids[r.ID] = true
	}
	return ids
}

// A rule created with FIREWALL_BLOCK_ACTION=drop in WAN_IN, whose database
// record is gone, survives the orphan sweep after the action and ruleset
// change, because the sweep keeps rules it could not have created. When its
// shard is pruned, the rule is deleted with the group instead of blocking the
// group's deletion. Rules of the user's are kept.
func TestRuleLeftByASettingsChangeIsDeletedWithItsGroup(t *testing.T) {
	ctx := context.Background()
	ctrl := testutil.NewMockController()
	store := newBboltStore(t)
	namer := testNamer(t)

	v4 := ensuredV4Shard(t, ctrl, store)
	groupID := v4.GroupIDs()[0]
	if err := newTestLegacyManager(ctrl, store, namer).EnsureRules(ctx, testSite, v4, nil); err != nil {
		t.Fatalf("EnsureRules: %v", err)
	}
	rules, err := ctrl.ListFirewallRules(ctx, testSite)
	if err != nil || len(rules) != 1 {
		t.Fatalf("rules after EnsureRules = %+v, %v; want one", rules, err)
	}
	stale := rules[0]
	// The classic API does not store descriptions, and the database record
	// was lost.
	stale.Description = ""
	user := controller.FirewallRule{ID: "user-rule", Name: "allow-monitoring", Action: "drop", Ruleset: "WAN_IN",
		SrcFirewallGroupIDs: []string{groupID}}
	other := controller.FirewallRule{ID: "other-group-rule", Name: "crowdsec-drop-v4-7", Action: "drop", Ruleset: "WAN_IN",
		SrcFirewallGroupIDs: []string{"group-of-another-instance"}}
	ctrl.SetRules(testSite, []controller.FirewallRule{stale, user, other})
	if err := store.DeletePolicy(cacheKey(testSite, stale.Name)); err != nil {
		t.Fatal(err)
	}

	changed := NewLegacyManager(LegacyConfig{
		RuleIndexStartV4: 22000, RuleIndexStartV6: 27000,
		RulesetV4: "LAN_IN", RulesetV6: "LANv6_IN",
		BlockAction: "reject", Description: "test",
	}, namer, ctrl, store, zerolog.Nop())
	noShards := NewShardManager(testSite, false, 5, namer, ctrl, store, zerolog.Nop(), 0, false, "legacy")
	if err := changed.EnsureRules(ctx, testSite, noShards, nil); err != nil {
		t.Fatalf("EnsureRules after the settings change: %v", err)
	}
	if !ruleIDs(t, ctrl)[stale.ID] {
		t.Fatal("the orphan sweep deleted a rule with another action and ruleset")
	}

	if err := changed.DeleteRuleForShard(ctx, testSite, groupID, false, 0); err != nil {
		t.Fatalf("DeleteRuleForShard: %v", err)
	}
	ids := ruleIDs(t, ctrl)
	if ids[stale.ID] {
		t.Error("the rule of the pruned shard is still on the controller")
	}
	if !ids[user.ID] || !ids[other.ID] {
		t.Errorf("rules left = %v; the user's rule and the rule of another group must stay", ids)
	}
}

// drain removes a rule the database has no record of when it uses a drained
// group, whatever its action and ruleset.
func TestDrainDeletesUnrecordedRuleOfADrainedGroup(t *testing.T) {
	ctx := context.Background()
	mgr, ctrl, store := newTestManager(t, defaultManagerConfig())
	groupName := "crowdsec-block-v4-0"
	ctrl.SetGroups(testSite, []controller.FirewallGroup{{ID: "group-1", Name: groupName, GroupType: "address-group",
		GroupMembers: []string{"198.51.100.10"}}})
	ctrl.SetRules(testSite, []controller.FirewallRule{
		{ID: "stale", Name: "crowdsec-drop-v4-0", Action: "reject", Ruleset: "LAN_IN", SrcFirewallGroupIDs: []string{"group-1"}},
		{ID: "user", Name: "custom-rule", Action: "drop", Ruleset: "WAN_IN", Description: "custom", SrcFirewallGroupIDs: []string{"group-1"}},
	})
	if err := store.SetGroup(cacheKey(testSite, groupName), storage.GroupRecord{UnifiID: "group-1", Site: testSite,
		Members: []string{"198.51.100.10"}}); err != nil {
		t.Fatal(err)
	}
	if err := mgr.PrepareDrain(ctx, []string{testSite}); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Drain(ctx, []string{testSite}); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	ids := ruleIDs(t, ctrl)
	if ids["stale"] {
		t.Error("drain left the unrecorded rule of the drained group")
	}
	if !ids["user"] {
		t.Error("drain deleted the user's rule")
	}
}

func TestDrainPreviewListsUnrecordedRuleOfADrainedGroup(t *testing.T) {
	ctx := context.Background()
	cfg := defaultManagerConfig()
	cfg.DryRun = true
	mgr, ctrl, _ := newTestManager(t, cfg)
	ctrl.SetGroups(testSite, []controller.FirewallGroup{{ID: "group-1", Name: "crowdsec-block-v4-0", GroupType: "address-group",
		GroupMembers: []string{"198.51.100.10"}}})
	ctrl.SetRules(testSite, []controller.FirewallRule{
		{ID: "stale", Name: "crowdsec-drop-v4-0", Action: "reject", Ruleset: "LAN_IN", SrcFirewallGroupIDs: []string{"group-1"}},
	})
	if err := mgr.PrepareDrain(ctx, []string{testSite}); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Drain(ctx, []string{testSite}); err != nil {
		t.Fatalf("Drain preview: %v", err)
	}
	if got := ctrl.Calls("DeleteFirewallRule"); got != 0 {
		t.Errorf("preview deleted %d rules", got)
	}
}

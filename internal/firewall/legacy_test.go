package firewall

import (
	"context"
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/rs/zerolog"
)

func newTestLegacyManager(ctrl controller.Controller, store storage.Store, namer *Namer) *LegacyManager {
	return NewLegacyManager(LegacyConfig{
		RuleIndexStartV4: 22000,
		RuleIndexStartV6: 27000,
		RulesetV4:        "WAN_IN",
		RulesetV6:        "WANv6_IN",
		BlockAction:      "drop",
		Description:      "test",
	}, namer, ctrl, store, zerolog.Nop())
}

func ensuredV4Shard(t *testing.T, ctrl controller.Controller, store storage.Store) *ShardManager {
	t.Helper()
	sm := NewShardManager(testSite, false, 5, testNamer(t), ctrl, store, zerolog.Nop(), 0, nil, false)
	if err := sm.EnsureShards(context.Background()); err != nil {
		t.Fatalf("EnsureShards: %v", err)
	}
	return sm
}

func ensuredV6Shard(t *testing.T, ctrl controller.Controller, store storage.Store) *ShardManager {
	t.Helper()
	sm := NewShardManager(testSite, true, 5, testNamer(t), ctrl, store, zerolog.Nop(), 0, nil, false)
	if err := sm.EnsureShards(context.Background()); err != nil {
		t.Fatalf("EnsureShards: %v", err)
	}
	return sm
}

func TestLegacyManager_EnsureRules_Create(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := newBboltStore(t)
	namer := testNamer(t)

	v4 := ensuredV4Shard(t, ctrl, store)
	lm := newTestLegacyManager(ctrl, store, namer)

	if err := lm.EnsureRules(context.Background(), testSite, v4, nil); err != nil {
		t.Fatalf("EnsureRules: %v", err)
	}

	// One CreateFirewallRule call for the single v4 shard
	if got := ctrl.Calls("CreateFirewallRule"); got != 1 {
		t.Errorf("CreateFirewallRule calls: got %d, want 1", got)
	}
}

func TestLegacyManager_EnsureRules_Idempotent(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := newBboltStore(t)
	namer := testNamer(t)

	v4 := ensuredV4Shard(t, ctrl, store)
	lm := newTestLegacyManager(ctrl, store, namer)

	// First call — creates the rule
	if err := lm.EnsureRules(context.Background(), testSite, v4, nil); err != nil {
		t.Fatalf("EnsureRules (first): %v", err)
	}

	// The rule was created and stored in bbolt; now the API should return it
	// (controller mock was updated by CreateFirewallRule, which added to rules list)
	firstCalls := ctrl.Calls("CreateFirewallRule")

	// Second call — rule exists in bbolt AND in API → no create call
	if err := lm.EnsureRules(context.Background(), testSite, v4, nil); err != nil {
		t.Fatalf("EnsureRules (second): %v", err)
	}

	if got := ctrl.Calls("CreateFirewallRule"); got != firstCalls {
		t.Errorf("second EnsureRules: CreateFirewallRule calls went from %d to %d; want no new calls",
			firstCalls, ctrl.Calls("CreateFirewallRule"))
	}
}

func TestLegacyManager_EnsureRules_RecreatesDeleted(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := newBboltStore(t)
	namer := testNamer(t)

	v4 := ensuredV4Shard(t, ctrl, store)
	lm := newTestLegacyManager(ctrl, store, namer)

	// First call — creates the rule and records it in bbolt
	if err := lm.EnsureRules(context.Background(), testSite, v4, nil); err != nil {
		t.Fatalf("EnsureRules (first): %v", err)
	}

	// Simulate rule being deleted from UniFi (clear the mock's rule list)
	ctrl.SetRules(testSite, nil)

	// Second call — bbolt has the policy record but the rule is gone from API
	if err := lm.EnsureRules(context.Background(), testSite, v4, nil); err != nil {
		t.Fatalf("EnsureRules (second): %v", err)
	}

	// Should have been recreated
	if got := ctrl.Calls("CreateFirewallRule"); got < 2 {
		t.Errorf("CreateFirewallRule calls: got %d, want >= 2 (initial + recreate)", got)
	}
}

func TestLegacyManager_EnsureRules_IPv6(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := newBboltStore(t)
	namer := testNamer(t)

	v4 := ensuredV4Shard(t, ctrl, store)
	v6 := ensuredV6Shard(t, ctrl, store)
	lm := newTestLegacyManager(ctrl, store, namer)

	if err := lm.EnsureRules(context.Background(), testSite, v4, v6); err != nil {
		t.Fatalf("EnsureRules: %v", err)
	}

	// Should create rules for both v4 and v6 shards
	if got := ctrl.Calls("CreateFirewallRule"); got < 2 {
		t.Errorf("CreateFirewallRule calls: got %d, want >= 2 (v4 + v6)", got)
	}

	// Verify one rule uses WANv6_IN ruleset
	rules, err := ctrl.ListFirewallRules(context.Background(), testSite)
	if err != nil {
		t.Fatal(err)
	}
	hasV6Rule := false
	for _, r := range rules {
		if r.Ruleset == "WANv6_IN" {
			hasV6Rule = true
			break
		}
	}
	if !hasV6Rule {
		t.Error("no WANv6_IN rule created for v6 shard")
	}
}

func TestLegacyManager_RuleIndex(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := newBboltStore(t)
	namer := testNamer(t)

	v4 := ensuredV4Shard(t, ctrl, store)
	lm := newTestLegacyManager(ctrl, store, namer)

	if err := lm.EnsureRules(context.Background(), testSite, v4, nil); err != nil {
		t.Fatalf("EnsureRules: %v", err)
	}

	rules, err := ctrl.ListFirewallRules(context.Background(), testSite)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) == 0 {
		t.Fatal("no rules created")
	}
	// First shard (index 0) should use RuleIndexStartV4 + 0 = 22000
	expected := 22000
	if rules[0].RuleIndex != expected {
		t.Errorf("RuleIndex: got %d, want %d", rules[0].RuleIndex, expected)
	}
}

// TestLegacyManager_EnsureRuleForShard_Create verifies that EnsureRuleForShard
// creates a rule for the given shard index when none exists.
func TestLegacyManager_EnsureRuleForShard_Create(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := newBboltStore(t)
	namer := testNamer(t)

	v4 := ensuredV4Shard(t, ctrl, store)
	lm := newTestLegacyManager(ctrl, store, namer)

	groupIDs := v4.GroupIDs()
	if len(groupIDs) == 0 {
		t.Fatal("expected at least one shard")
	}

	if err := lm.EnsureRuleForShard(context.Background(), testSite, groupIDs[0], false, 0); err != nil {
		t.Fatalf("EnsureRuleForShard: %v", err)
	}

	if got := ctrl.Calls("CreateFirewallRule"); got != 1 {
		t.Errorf("CreateFirewallRule calls: got %d, want 1", got)
	}
}

// TestLegacyManager_EnsureRuleForShard_Idempotent verifies that calling
// EnsureRuleForShard twice does not create a duplicate rule.
func TestLegacyManager_EnsureRuleForShard_Idempotent(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := newBboltStore(t)
	namer := testNamer(t)

	v4 := ensuredV4Shard(t, ctrl, store)
	lm := newTestLegacyManager(ctrl, store, namer)

	groupIDs := v4.GroupIDs()
	if err := lm.EnsureRuleForShard(context.Background(), testSite, groupIDs[0], false, 0); err != nil {
		t.Fatalf("EnsureRuleForShard (first): %v", err)
	}
	firstCalls := ctrl.Calls("CreateFirewallRule")

	if err := lm.EnsureRuleForShard(context.Background(), testSite, groupIDs[0], false, 0); err != nil {
		t.Fatalf("EnsureRuleForShard (second): %v", err)
	}
	if got := ctrl.Calls("CreateFirewallRule"); got != firstCalls {
		t.Errorf("second EnsureRuleForShard: CreateFirewallRule went from %d to %d; want no new calls",
			firstCalls, ctrl.Calls("CreateFirewallRule"))
	}
}

// TestLegacyManager_DeleteRuleForShard verifies that DeleteRuleForShard removes
// the rule and its bbolt record.
func TestLegacyManager_DeleteRuleForShard(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := newBboltStore(t)
	namer := testNamer(t)

	v4 := ensuredV4Shard(t, ctrl, store)
	lm := newTestLegacyManager(ctrl, store, namer)

	groupIDs := v4.GroupIDs()
	// Create first
	if err := lm.EnsureRuleForShard(context.Background(), testSite, groupIDs[0], false, 0); err != nil {
		t.Fatalf("EnsureRuleForShard: %v", err)
	}

	// Delete
	if err := lm.DeleteRuleForShard(context.Background(), testSite, false, 0); err != nil {
		t.Fatalf("DeleteRuleForShard: %v", err)
	}

	if got := ctrl.Calls("DeleteFirewallRule"); got != 1 {
		t.Errorf("DeleteFirewallRule calls: got %d, want 1", got)
	}
}

// TestLegacyManager_DeleteRuleForShard_NoOp verifies that DeleteRuleForShard
// is a no-op when no rule record exists.
func TestLegacyManager_DeleteRuleForShard_NoOp(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := newBboltStore(t)
	namer := testNamer(t)

	lm := newTestLegacyManager(ctrl, store, namer)

	// No rule was ever created
	if err := lm.DeleteRuleForShard(context.Background(), testSite, false, 0); err != nil {
		t.Fatalf("DeleteRuleForShard (no-op): %v", err)
	}
	if got := ctrl.Calls("DeleteFirewallRule"); got != 0 {
		t.Errorf("DeleteFirewallRule calls: got %d, want 0 (no-op)", got)
	}
}

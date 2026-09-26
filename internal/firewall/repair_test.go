package firewall

import (
	"context"
	"errors"
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
)

// TestEnsureRuleForShard_RepairsDrift verifies that an existing rule for a new
// shard is checked and repaired, not trusted because its ID is cached.
func TestEnsureRuleForShard_RepairsDrift(t *testing.T) {
	tests := []struct {
		name       string
		drift      func(r *controller.FirewallRule)
		wantUpdate bool
	}{
		{name: "unchanged", drift: func(*controller.FirewallRule) {}},
		{name: "points at another group", drift: func(r *controller.FirewallRule) { r.SrcFirewallGroupIDs = []string{"other"} }, wantUpdate: true},
		{name: "disabled", drift: func(r *controller.FirewallRule) { r.Enabled = false }, wantUpdate: true},
		{name: "moved index", drift: func(r *controller.FirewallRule) { r.RuleIndex = 1 }, wantUpdate: true},
		// The classic API does not store descriptions: rewriting every rule on
		// every reconcile would never converge.
		{name: "description not stored", drift: func(r *controller.FirewallRule) { r.Description = "" }},
		{name: "description changed", drift: func(r *controller.FirewallRule) { r.Description = "edited" }, wantUpdate: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			ctrl := testutil.NewMockController()
			store := newBboltStore(t)
			v4 := ensuredV4Shard(t, ctrl, store)
			lm := newTestLegacyManager(ctrl, store, testNamer(t))
			groupID := v4.GroupIDs()[0]
			if err := lm.EnsureRuleForShard(ctx, testSite, groupID, false, 0); err != nil {
				t.Fatalf("first EnsureRuleForShard: %v", err)
			}

			rules, _ := ctrl.ListFirewallRules(ctx, testSite)
			if len(rules) != 1 {
				t.Fatalf("rules = %+v, want 1", rules)
			}
			tt.drift(&rules[0])
			ctrl.SetRules(testSite, rules)
			creates, updates := ctrl.Calls("CreateFirewallRule"), ctrl.Calls("UpdateFirewallRule")

			if err := lm.EnsureRuleForShard(ctx, testSite, groupID, false, 0); err != nil {
				t.Fatalf("second EnsureRuleForShard: %v", err)
			}
			if got := ctrl.Calls("CreateFirewallRule"); got != creates {
				t.Errorf("CreateFirewallRule calls = %d, want %d", got, creates)
			}
			if got := ctrl.Calls("UpdateFirewallRule") - updates; (got == 1) != tt.wantUpdate {
				t.Errorf("UpdateFirewallRule calls = %d, want update %v", got, tt.wantUpdate)
			}
			rules, _ = ctrl.ListFirewallRules(ctx, testSite)
			r := rules[0]
			if !r.Enabled || r.RuleIndex != 22000 || len(r.SrcFirewallGroupIDs) != 1 || r.SrcFirewallGroupIDs[0] != groupID {
				t.Errorf("rule after ensure = %+v", r)
			}
		})
	}
}

// TestEnsureRuleForShard_AdoptsAfterCacheLoss verifies that a rule the bouncer
// created is adopted by name once its cached ID is gone. The classic API does
// not store descriptions, so a listed rule has an empty one.
func TestEnsureRuleForShard_AdoptsAfterCacheLoss(t *testing.T) {
	tests := []struct {
		name        string
		description string
		wantErr     bool
	}{
		{name: "description not stored by controller", description: ""},
		{name: "matching description", description: "test"}, // lm.cfg.Description
		{name: "foreign rule with same name", description: "someone else's rule", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			ctrl := testutil.NewMockController()
			store := newBboltStore(t)
			v4 := ensuredV4Shard(t, ctrl, store)
			lm := newTestLegacyManager(ctrl, store, testNamer(t))
			groupID := v4.GroupIDs()[0]
			if err := lm.EnsureRuleForShard(ctx, testSite, groupID, false, 0); err != nil {
				t.Fatalf("first EnsureRuleForShard: %v", err)
			}
			rules, _ := ctrl.ListFirewallRules(ctx, testSite)
			rules[0].Description = tt.description
			ctrl.SetRules(testSite, rules)
			if err := deleteCachedPolicy(store, testSite, rules[0].Name); err != nil {
				t.Fatalf("clear cache: %v", err)
			}
			creates := ctrl.Calls("CreateFirewallRule")

			err := lm.EnsureRuleForShard(ctx, testSite, groupID, false, 0)
			if (err != nil) != tt.wantErr {
				t.Fatalf("EnsureRuleForShard error = %v, want error %v", err, tt.wantErr)
			}
			if got := ctrl.Calls("CreateFirewallRule"); got != creates {
				t.Errorf("CreateFirewallRule calls = %d, want %d (no duplicate)", got, creates)
			}
		})
	}
}

// TestEnsurePoliciesForShard_RepairsDrift verifies that an existing zone
// policy for a new shard is repaired in place.
func TestEnsurePoliciesForShard_RepairsDrift(t *testing.T) {
	ctx := context.Background()
	ctrl := testutil.NewMockController()
	store := testutil.NewMockStore()
	v4 := ensuredZoneV4Shard(t, ctrl, store)
	zm := newTestZoneManager(ctrl, store, zoneTestNamer(t))
	if err := zm.Bootstrap(ctx, []string{testSite}); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	groupID := v4.GroupIDs()[0]
	if err := zm.EnsurePoliciesForShard(ctx, testSite, groupID, false, 0); err != nil {
		t.Fatalf("first EnsurePoliciesForShard: %v", err)
	}
	policies, _ := ctrl.ListZonePolicies(ctx, testSite)
	policies[0].Enabled = false
	policies[0].TrafficMatchingListIDs = []string{"other"}
	ctrl.SetPolicies(testSite, policies)
	creates := ctrl.Calls("CreateZonePolicy")

	if err := zm.EnsurePoliciesForShard(ctx, testSite, groupID, false, 0); err != nil {
		t.Fatalf("second EnsurePoliciesForShard: %v", err)
	}
	if got := ctrl.Calls("CreateZonePolicy"); got != creates {
		t.Errorf("CreateZonePolicy calls = %d, want %d", got, creates)
	}
	policies, _ = ctrl.ListZonePolicies(ctx, testSite)
	if p := policies[0]; !p.Enabled || len(p.TrafficMatchingListIDs) != 1 || p.TrafficMatchingListIDs[0] != groupID {
		t.Errorf("policy after repair = %+v", p)
	}
}

// TestEnsurePolicy_UpdateNotFound covers a 404 on a policy update. Only a
// listing that no longer shows the policy may lead to a create; anything else
// is transient and must not duplicate the policy.
func TestEnsurePolicy_UpdateNotFound(t *testing.T) {
	const staleID = "policy-1"
	tests := []struct {
		name        string
		listed      []string // IDs listed under the policy's name after the 404
		listErr     error
		wantErr     bool
		wantCreates int
		wantCached  string
	}{
		{name: "still listed: transient", listed: []string{staleID}, wantErr: true, wantCached: staleID},
		{name: "listing fails: transient", listErr: errors.New("controller starting"), wantErr: true, wantCached: staleID},
		{name: "listed under a new ID: adopted next pass", listed: []string{"policy-2"}, wantErr: true, wantCached: "policy-2"},
		{name: "gone: recreated", wantCreates: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			ctrl := testutil.NewMockController()
			store := testutil.NewMockStore()
			zm := newTestZoneManager(ctrl, store, zoneTestNamer(t))
			desired, err := zm.desiredPolicy(testSite, config.ZonePair{Src: "wan", Dst: "lan"},
				map[string]string{"wan": "zone-wan", "lan": "zone-lan"}, false, 0, "tml-0")
			if err != nil {
				t.Fatalf("desiredPolicy: %v", err)
			}
			stale := desired
			stale.ID = staleID
			stale.LoggingEnabled = !desired.LoggingEnabled // drifted, so ensurePolicy updates it
			existingByID := map[string]controller.ZonePolicy{staleID: stale}

			var listed []controller.ZonePolicy
			for _, id := range tt.listed {
				p := stale
				p.ID = id
				listed = append(listed, p)
			}
			ctrl.SetPolicies(testSite, listed)
			ctrl.SetError("UpdateZonePolicy", &controller.ErrNotFound{URL: "/policies/" + staleID})
			if tt.listErr != nil {
				ctrl.SetError("ListZonePolicies", tt.listErr)
			}

			_, err = zm.ensurePolicy(ctx, testSite, desired, existingByID, false)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ensurePolicy err = %v, wantErr %v", err, tt.wantErr)
			}
			if got := ctrl.Calls("CreateZonePolicy"); got != tt.wantCreates {
				t.Errorf("CreateZonePolicy calls = %d, want %d", got, tt.wantCreates)
			}
			if tt.wantCached != "" {
				rec, err := getCachedPolicy(store, testSite, desired.Name)
				if err != nil || rec == nil || rec.UnifiID != tt.wantCached {
					t.Errorf("cached policy = %+v, %v; want ID %q", rec, err, tt.wantCached)
				}
			}
		})
	}
}

func TestNeedsUpdateZonePolicy(t *testing.T) {
	desired := controller.ZonePolicy{
		Enabled: true, Action: "BLOCK", SrcZone: "a", DstZone: "b", IPVersion: "IPV4", Description: "d",
		TrafficMatchingListIDs: []string{"t"}, ConnectionStateFilter: []string{"NEW", "INVALID"},
	}
	tests := []struct {
		name   string
		mutate func(p *controller.ZonePolicy)
		want   bool
	}{
		{name: "equal", mutate: func(*controller.ZonePolicy) {}},
		{name: "state order ignored", mutate: func(p *controller.ZonePolicy) { p.ConnectionStateFilter = []string{"INVALID", "NEW"} }},
		{name: "ID and index ignored", mutate: func(p *controller.ZonePolicy) { p.ID = "x"; i := 3; p.Index = &i }},
		{name: "disabled", mutate: func(p *controller.ZonePolicy) { p.Enabled = false }, want: true},
		{name: "action", mutate: func(p *controller.ZonePolicy) { p.Action = "ALLOW" }, want: true},
		{name: "zone", mutate: func(p *controller.ZonePolicy) { p.DstZone = "c" }, want: true},
		{name: "source list", mutate: func(p *controller.ZonePolicy) { p.TrafficMatchingListIDs = []string{"u"} }, want: true},
		{name: "extra source list", mutate: func(p *controller.ZonePolicy) { p.TrafficMatchingListIDs = []string{"t", "u"} }, want: true},
		{name: "port filter", mutate: func(p *controller.ZonePolicy) { p.DstPortTMLID = "ports" }, want: true},
		{name: "logging", mutate: func(p *controller.ZonePolicy) { p.LoggingEnabled = true }, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			current := desired
			current.TrafficMatchingListIDs = append([]string(nil), desired.TrafficMatchingListIDs...)
			current.ConnectionStateFilter = append([]string(nil), desired.ConnectionStateFilter...)
			tt.mutate(&current)
			if got := needsUpdateZonePolicy(current, desired); got != tt.want {
				t.Errorf("needsUpdateZonePolicy = %v, want %v", got, tt.want)
			}
		})
	}
}

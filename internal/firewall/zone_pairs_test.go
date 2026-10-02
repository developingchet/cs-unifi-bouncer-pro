package firewall

import (
	"context"
	"errors"
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
)

// TestEmptyZonePairsNeverDeleteBlockPolicies: with no zone pair configured,
// no block policy is expected, so provisioning and reload refuse to run
// rather than sweep every existing policy as an orphan.
func TestEmptyZonePairsNeverDeleteBlockPolicies(t *testing.T) {
	ctx := context.Background()
	f := newStagedPolicyFixture(t)

	if err := f.zm.Reload(ctx, []string{testSite}, nil); err == nil {
		t.Error("Reload accepted an empty zone pair set")
	}
	if got := len(f.zm.cfg.ZonePairs); got != 1 {
		t.Errorf("zone pairs after a rejected reload = %d, want the original 1", got)
	}

	f.zm.cfg.ZonePairs = nil
	if err := f.zm.EnsurePolicies(ctx, testSite, f.shard, nil); err == nil {
		t.Error("EnsurePolicies ran with no zone pairs")
	}
	if got := f.ctrl.Calls("DeleteZonePolicy"); got != 0 {
		t.Errorf("DeleteZonePolicy called %d times with no zone pairs", got)
	}
	if names := f.policyNames(t); len(names) != 1 || names[0] != f.block.Name {
		t.Errorf("policies = %v, want the block policy untouched", names)
	}
}

func TestLoadInfrastructureRejectsZoneModeWithoutZonePairs(t *testing.T) {
	cfg := defaultManagerConfig()
	cfg.FirewallMode = "auto"
	mgr, ctrl, _ := newTestManager(t, cfg)
	ctrl.SetHasFeature(testSite, controller.FeatureZoneBasedFirewall, true)

	err := mgr.LoadInfrastructure(context.Background(), []string{testSite})
	if !errors.Is(err, errNoZonePairs) {
		t.Fatalf("LoadInfrastructure error = %v, want errNoZonePairs", err)
	}
}

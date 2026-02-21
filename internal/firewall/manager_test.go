package firewall

import (
	"context"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/rs/zerolog"
)

// defaultManagerConfig returns a ManagerConfig suitable for most manager tests.
func defaultManagerConfig() ManagerConfig {
	return ManagerConfig{
		FirewallMode:    "legacy",
		EnableIPv6:      false,
		GroupCapacityV4: 5,
		GroupCapacityV6: 5,
		BatchWindow:     10 * time.Millisecond,
		DryRun:          false,
		LegacyCfg: LegacyConfig{
			RuleIndexStartV4: 22000,
			RuleIndexStartV6: 27000,
			RulesetV4:        "WAN_IN",
			RulesetV6:        "WANv6_IN",
			BlockAction:      "drop",
			Description:      "test",
		},
		ZoneCfg: ZoneConfig{
			Description: "test",
		},
	}
}

// newTestManager builds a Manager with a MockController and MockStore.
func newTestManager(t *testing.T, cfg ManagerConfig) (Manager, *testutil.MockController, *testutil.MockStore) {
	t.Helper()
	ctrl := testutil.NewMockController()
	store := testutil.NewMockStore()
	namer := managerTestNamer(t)
	mgr := NewManager(cfg, ctrl, store, namer, zerolog.Nop())
	return mgr, ctrl, store
}

// managerTestNamer returns a Namer using the default templates.
func managerTestNamer(t *testing.T) *Namer {
	t.Helper()
	n, err := NewNamer(
		"crowdsec-block-{{.Family}}-{{.Index}}",
		"crowdsec-drop-{{.Family}}-{{.Index}}",
		"crowdsec-policy-{{.SrcZone}}-{{.DstZone}}-{{.Family}}-{{.Index}}",
		"test",
	)
	if err != nil {
		t.Fatalf("NewNamer: %v", err)
	}
	return n
}

// TestEnsureInfrastructure_LegacyMode verifies that in legacy mode,
// EnsureInfrastructure calls CreateFirewallRule for the v4 shard.
func TestEnsureInfrastructure_LegacyMode(t *testing.T) {
	cfg := defaultManagerConfig()
	cfg.FirewallMode = "legacy"

	mgr, ctrl, _ := newTestManager(t, cfg)
	if err := mgr.EnsureInfrastructure(context.Background(), []string{testSite}); err != nil {
		t.Fatalf("EnsureInfrastructure: %v", err)
	}

	if got := ctrl.Calls("CreateFirewallRule"); got < 1 {
		t.Errorf("CreateFirewallRule calls: got %d, want >= 1", got)
	}
}

// TestEnsureInfrastructure_ZoneMode verifies that in zone mode,
// EnsureInfrastructure calls CreateZonePolicy.
func TestEnsureInfrastructure_ZoneMode(t *testing.T) {
	cfg := defaultManagerConfig()
	cfg.FirewallMode = "zone"
	cfg.ZoneCfg.ZonePairs = []config.ZonePair{{Src: "wan", Dst: "lan"}}

	mgr, ctrl, _ := newTestManager(t, cfg)
	if err := mgr.EnsureInfrastructure(context.Background(), []string{testSite}); err != nil {
		t.Fatalf("EnsureInfrastructure: %v", err)
	}

	if got := ctrl.Calls("CreateZonePolicy"); got < 1 {
		t.Errorf("CreateZonePolicy calls: got %d, want >= 1", got)
	}
}

// TestEnsureInfrastructure_AutoMode_Zone verifies that in auto mode, when the
// controller reports zone-based firewall support, zone policies are created.
func TestEnsureInfrastructure_AutoMode_Zone(t *testing.T) {
	cfg := defaultManagerConfig()
	cfg.FirewallMode = "auto"
	cfg.ZoneCfg.ZonePairs = []config.ZonePair{{Src: "wan", Dst: "lan"}}

	mgr, ctrl, _ := newTestManager(t, cfg)
	ctrl.SetHasFeature(testSite, controller.FeatureZoneBasedFirewall, true)

	if err := mgr.EnsureInfrastructure(context.Background(), []string{testSite}); err != nil {
		t.Fatalf("EnsureInfrastructure: %v", err)
	}

	if got := ctrl.Calls("CreateZonePolicy"); got < 1 {
		t.Errorf("CreateZonePolicy calls: got %d, want >= 1", got)
	}
	if got := ctrl.Calls("CreateFirewallRule"); got != 0 {
		t.Errorf("CreateFirewallRule calls: got %d, want 0 (should use zone path)", got)
	}
}

// TestEnsureInfrastructure_AutoMode_Legacy verifies that in auto mode, when the
// controller reports no zone-based firewall support, legacy rules are created.
func TestEnsureInfrastructure_AutoMode_Legacy(t *testing.T) {
	cfg := defaultManagerConfig()
	cfg.FirewallMode = "auto"

	mgr, ctrl, _ := newTestManager(t, cfg)
	ctrl.SetHasFeature(testSite, controller.FeatureZoneBasedFirewall, false)

	if err := mgr.EnsureInfrastructure(context.Background(), []string{testSite}); err != nil {
		t.Fatalf("EnsureInfrastructure: %v", err)
	}

	if got := ctrl.Calls("CreateFirewallRule"); got < 1 {
		t.Errorf("CreateFirewallRule calls: got %d, want >= 1 (should fall back to legacy)", got)
	}
}

// TestEnsureInfrastructure_AutoMode_FeatureError verifies that when HasFeature
// returns an error, the manager falls back to legacy mode gracefully.
func TestEnsureInfrastructure_AutoMode_FeatureError(t *testing.T) {
	cfg := defaultManagerConfig()
	cfg.FirewallMode = "auto"

	mgr, ctrl, _ := newTestManager(t, cfg)
	ctrl.SetError("HasFeature", errTest("feature detection failed"))

	// Should not return an error — falls back to legacy.
	if err := mgr.EnsureInfrastructure(context.Background(), []string{testSite}); err != nil {
		t.Fatalf("EnsureInfrastructure: %v", err)
	}

	if got := ctrl.Calls("CreateFirewallRule"); got < 1 {
		t.Errorf("CreateFirewallRule calls: got %d, want >= 1 (fallback to legacy)", got)
	}
}

// TestApplyBan_DryRun verifies that when DryRun is enabled, no API mutation
// methods are called.
func TestApplyBan_DryRun(t *testing.T) {
	cfg := defaultManagerConfig()
	cfg.DryRun = true

	mgr, ctrl, _ := newTestManager(t, cfg)

	// DryRun returns early before touching any shard manager, so EnsureInfrastructure
	// is not required first.
	err := mgr.ApplyBan(context.Background(), testSite, "10.0.0.1", false)
	if err != nil {
		t.Fatalf("ApplyBan (dry-run): %v", err)
	}

	if got := ctrl.Calls("CreateFirewallGroup"); got != 0 {
		t.Errorf("CreateFirewallGroup calls: got %d, want 0 (dry-run)", got)
	}
	if got := ctrl.Calls("UpdateFirewallGroup"); got != 0 {
		t.Errorf("UpdateFirewallGroup calls: got %d, want 0 (dry-run)", got)
	}
}

// TestApplyBan_Basic verifies that applying a ban to a known site succeeds.
func TestApplyBan_Basic(t *testing.T) {
	cfg := defaultManagerConfig()

	mgr, ctrl, _ := newTestManager(t, cfg)
	if err := mgr.EnsureInfrastructure(context.Background(), []string{testSite}); err != nil {
		t.Fatalf("EnsureInfrastructure: %v", err)
	}

	if err := mgr.ApplyBan(context.Background(), testSite, "10.0.0.1", false); err != nil {
		t.Fatalf("ApplyBan: %v", err)
	}

	// Verify the group was created during EnsureInfrastructure.
	if got := ctrl.Calls("CreateFirewallGroup"); got < 1 {
		t.Errorf("CreateFirewallGroup calls: got %d, want >= 1", got)
	}
}

// TestApplyBan_UnknownSite verifies that banning on a site that has not been
// initialized returns an error.
func TestApplyBan_UnknownSite(t *testing.T) {
	cfg := defaultManagerConfig()
	mgr, _, _ := newTestManager(t, cfg)

	err := mgr.ApplyBan(context.Background(), "unknown-site", "10.0.0.1", false)
	if err == nil {
		t.Error("ApplyBan on unknown site: expected error, got nil")
	}
}

// TestApplyUnban_Basic verifies that unbanning after a ban succeeds.
func TestApplyUnban_Basic(t *testing.T) {
	cfg := defaultManagerConfig()

	mgr, _, _ := newTestManager(t, cfg)
	if err := mgr.EnsureInfrastructure(context.Background(), []string{testSite}); err != nil {
		t.Fatalf("EnsureInfrastructure: %v", err)
	}

	if err := mgr.ApplyBan(context.Background(), testSite, "10.0.0.1", false); err != nil {
		t.Fatalf("ApplyBan: %v", err)
	}

	if err := mgr.ApplyUnban(context.Background(), testSite, "10.0.0.1", false); err != nil {
		t.Fatalf("ApplyUnban: %v", err)
	}
}

// TestApplyUnban_UnknownSite verifies that unbanning on an unknown site is
// idempotent (no error, no panic).
func TestApplyUnban_UnknownSite(t *testing.T) {
	cfg := defaultManagerConfig()
	mgr, _, _ := newTestManager(t, cfg)

	err := mgr.ApplyUnban(context.Background(), "unknown-site", "10.0.0.1", false)
	if err != nil {
		t.Errorf("ApplyUnban on unknown site: expected nil, got %v", err)
	}
}

// TestReconcile_AddsMissing verifies that Reconcile adds an IP to the shard
// when the store has it but the shard does not (UpdateFirewallGroup is called).
func TestReconcile_AddsMissing(t *testing.T) {
	cfg := defaultManagerConfig()

	mgr, ctrl, store := newTestManager(t, cfg)
	if err := mgr.EnsureInfrastructure(context.Background(), []string{testSite}); err != nil {
		t.Fatalf("EnsureInfrastructure: %v", err)
	}

	// Put an IP in the ban list.
	if err := store.BanRecord("10.0.0.99", time.Time{}, false); err != nil {
		t.Fatalf("BanRecord: %v", err)
	}

	result, err := mgr.Reconcile(context.Background(), []string{testSite})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.Added < 1 {
		t.Errorf("Reconcile.Added: got %d, want >= 1", result.Added)
	}
	if got := ctrl.Calls("UpdateFirewallGroup"); got < 1 {
		t.Errorf("UpdateFirewallGroup calls: got %d, want >= 1 (flush after reconcile)", got)
	}
}

// TestReconcile_RemovesExtra verifies that Reconcile removes an IP from the
// shard when the shard has it but the store does not.
func TestReconcile_RemovesExtra(t *testing.T) {
	cfg := defaultManagerConfig()

	mgr, ctrl, _ := newTestManager(t, cfg)
	if err := mgr.EnsureInfrastructure(context.Background(), []string{testSite}); err != nil {
		t.Fatalf("EnsureInfrastructure: %v", err)
	}

	// Put an IP directly into the shard (bypassing the store).
	mi := mgr.(*managerImpl)
	mi.mu.RLock()
	v4 := mi.v4Mgrs[testSite]
	mi.mu.RUnlock()

	if _, _, err := v4.Add(context.Background(), "10.0.0.99"); err != nil {
		t.Fatalf("direct shard Add: %v", err)
	}

	// Store has no bans, so 10.0.0.99 is extra.
	result, err := mgr.Reconcile(context.Background(), []string{testSite})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.Removed < 1 {
		t.Errorf("Reconcile.Removed: got %d, want >= 1", result.Removed)
	}
	if got := ctrl.Calls("UpdateFirewallGroup"); got < 1 {
		t.Errorf("UpdateFirewallGroup calls: got %d, want >= 1 (flush after reconcile)", got)
	}
}

// TestIPv6Disabled verifies that when EnableIPv6 is false, no v6 shard manager
// is created (v6Mgrs stays empty for the site).
func TestIPv6Disabled(t *testing.T) {
	cfg := defaultManagerConfig()
	cfg.EnableIPv6 = false

	mgr, _, _ := newTestManager(t, cfg)
	if err := mgr.EnsureInfrastructure(context.Background(), []string{testSite}); err != nil {
		t.Fatalf("EnsureInfrastructure: %v", err)
	}

	mi := mgr.(*managerImpl)
	mi.mu.RLock()
	_, hasV6 := mi.v6Mgrs[testSite]
	mi.mu.RUnlock()

	if hasV6 {
		t.Error("v6Mgrs should be empty when EnableIPv6=false")
	}
}

// TestApplyBan_OverflowProvisionRule verifies that when ApplyBan causes a new
// shard to be created (capacity overflow), a firewall rule is provisioned for
// the new shard.
func TestApplyBan_OverflowProvisionRule(t *testing.T) {
	cfg := defaultManagerConfig()
	cfg.FirewallMode = "legacy"
	cfg.GroupCapacityV4 = 1 // capacity=1 so second IP forces new shard

	mgr, ctrl, _ := newTestManager(t, cfg)
	if err := mgr.EnsureInfrastructure(context.Background(), []string{testSite}); err != nil {
		t.Fatalf("EnsureInfrastructure: %v", err)
	}

	// First IP fills shard 0 (rule already created by EnsureInfrastructure)
	if err := mgr.ApplyBan(context.Background(), testSite, "10.0.0.1", false); err != nil {
		t.Fatalf("ApplyBan (first IP): %v", err)
	}

	rulesAfterFirst := ctrl.Calls("CreateFirewallRule")

	// Second IP overflows into shard 1 → new rule must be created
	if err := mgr.ApplyBan(context.Background(), testSite, "10.0.0.2", false); err != nil {
		t.Fatalf("ApplyBan (overflow IP): %v", err)
	}

	if got := ctrl.Calls("CreateFirewallRule"); got <= rulesAfterFirst {
		t.Errorf("CreateFirewallRule calls: got %d, want > %d (new shard needs a rule)", got, rulesAfterFirst)
	}
}

// --- helpers ----------------------------------------------------------------

// errTest is a simple error type for injection.
type errTest string

func (e errTest) Error() string { return string(e) }

// TestDryRunNoWrites verifies that when DryRun=true, no write operations
// are sent to the controller. Uses a PanicController that panics on any
// write method call to ensure the gates are working.
func TestDryRunNoWrites(t *testing.T) {
	cfg := defaultManagerConfig()
	cfg.DryRun = true
	cfg.FirewallMode = "legacy"

	ctrl := NewPanicController()
	store := testutil.NewMockStore()
	namer := managerTestNamer(t)
	mgr := NewManager(cfg, ctrl, store, namer, zerolog.Nop())

	ctx := context.Background()

	// EnsureInfrastructure should NOT panic (dry run gates all writes)
	if err := mgr.EnsureInfrastructure(ctx, []string{testSite}); err != nil {
		t.Fatalf("EnsureInfrastructure: %v", err)
	}

	// Populate bbolt with a fake ban entry so reconcile has something to do
	if err := store.BanRecord("203.0.113.42", time.Now().Add(1*time.Hour), false); err != nil {
		t.Fatalf("BanRecord: %v", err)
	}

	// Reconcile should NOT panic (dry run gates all writes)
	result, err := mgr.Reconcile(ctx, []string{testSite})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result == nil {
		t.Fatal("Reconcile returned nil result")
	}

	// ApplyBan should NOT panic (dry run gates writes)
	if err := mgr.ApplyBan(ctx, testSite, "198.51.100.1", false); err != nil {
		t.Fatalf("ApplyBan: %v", err)
	}

	// ApplyUnban should NOT panic (dry run gates writes)
	if err := mgr.ApplyUnban(ctx, testSite, "203.0.113.42", false); err != nil {
		t.Fatalf("ApplyUnban: %v", err)
	}

	// Verify that bbolt was never written to in dry run
	bans, err := store.BanList()
	if err != nil {
		t.Fatalf("BanList: %v", err)
	}
	// Should still only have the one entry we manually added (ApplyBan/ApplyUnban didn't write)
	if len(bans) != 1 {
		t.Errorf("BanList had %d entries, want 1 (only the pre-existing one)", len(bans))
	}
}

// PanicController implements controller.Controller and panics
// on any write method to verify that DryRun gates are preventing writes.
type PanicController struct{}

func NewPanicController() *PanicController {
	return &PanicController{}
}

func (pc *PanicController) ListFirewallGroups(ctx context.Context, site string) ([]controller.FirewallGroup, error) {
	return []controller.FirewallGroup{}, nil
}

func (pc *PanicController) CreateFirewallGroup(ctx context.Context, site string, g controller.FirewallGroup) (controller.FirewallGroup, error) {
	panic("DryRun gate failed: CreateFirewallGroup called")
}

func (pc *PanicController) UpdateFirewallGroup(ctx context.Context, site string, g controller.FirewallGroup) error {
	panic("DryRun gate failed: UpdateFirewallGroup called")
}

func (pc *PanicController) DeleteFirewallGroup(ctx context.Context, site string, id string) error {
	panic("DryRun gate failed: DeleteFirewallGroup called")
}

func (pc *PanicController) ListFirewallRules(ctx context.Context, site string) ([]controller.FirewallRule, error) {
	return []controller.FirewallRule{}, nil
}

func (pc *PanicController) CreateFirewallRule(ctx context.Context, site string, r controller.FirewallRule) (controller.FirewallRule, error) {
	panic("DryRun gate failed: CreateFirewallRule called")
}

func (pc *PanicController) UpdateFirewallRule(ctx context.Context, site string, r controller.FirewallRule) error {
	panic("DryRun gate failed: UpdateFirewallRule called")
}

func (pc *PanicController) DeleteFirewallRule(ctx context.Context, site string, id string) error {
	panic("DryRun gate failed: DeleteFirewallRule called")
}

func (pc *PanicController) ListZonePolicies(ctx context.Context, site string) ([]controller.ZonePolicy, error) {
	return []controller.ZonePolicy{}, nil
}

func (pc *PanicController) CreateZonePolicy(ctx context.Context, site string, p controller.ZonePolicy) (controller.ZonePolicy, error) {
	panic("DryRun gate failed: CreateZonePolicy called")
}

func (pc *PanicController) UpdateZonePolicy(ctx context.Context, site string, p controller.ZonePolicy) error {
	panic("DryRun gate failed: UpdateZonePolicy called")
}

func (pc *PanicController) DeleteZonePolicy(ctx context.Context, site string, id string) error {
	panic("DryRun gate failed: DeleteZonePolicy called")
}

func (pc *PanicController) ReorderZonePolicies(ctx context.Context, site string, orderedIDs []string) error {
	panic("DryRun gate failed: ReorderZonePolicies called")
}

func (pc *PanicController) ListZones(ctx context.Context, site string) ([]controller.Zone, error) {
	return []controller.Zone{}, nil
}

func (pc *PanicController) HasFeature(ctx context.Context, site string, feature string) (bool, error) {
	return false, nil
}

func (pc *PanicController) Ping(ctx context.Context) error {
	return nil
}

func (pc *PanicController) Close() error {
	return nil
}

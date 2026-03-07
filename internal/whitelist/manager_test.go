package whitelist

import (
	"context"
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/rs/zerolog"
)

// TestTMLItemsEqual_Symmetric tests that order doesn't matter.
func TestTMLItemsEqual_Symmetric(t *testing.T) {
	existing := []controller.TrafficMatchingListItem{
		{Value: "1.1.1.0/24"},
		{Value: "2.2.2.0/24"},
		{Value: "3.3.3.0/24"},
	}
	desired := []controller.TrafficMatchingListItem{
		{Value: "3.3.3.0/24"},
		{Value: "1.1.1.0/24"},
		{Value: "2.2.2.0/24"},
	}

	if !tmlItemsEqual(existing, desired) {
		t.Error("expected items to equal (order-independent)")
	}
}

// TestTMLItemsEqual_LengthMismatch tests that different lengths return false.
func TestTMLItemsEqual_LengthMismatch(t *testing.T) {
	existing := []controller.TrafficMatchingListItem{
		{Value: "1.1.1.0/24"},
		{Value: "2.2.2.0/24"},
	}
	desired := []controller.TrafficMatchingListItem{
		{Value: "1.1.1.0/24"},
		{Value: "2.2.2.0/24"},
		{Value: "3.3.3.0/24"},
	}

	if tmlItemsEqual(existing, desired) {
		t.Error("expected items to NOT equal (different lengths)")
	}
}

// TestTMLItemsEqual_Empty tests that empty lists are equal.
func TestTMLItemsEqual_Empty(t *testing.T) {
	existing := []controller.TrafficMatchingListItem{}
	desired := []controller.TrafficMatchingListItem{}

	if !tmlItemsEqual(existing, desired) {
		t.Error("expected empty items to be equal")
	}
}

// TestTMLItemsEqual_Single tests single element lists.
func TestTMLItemsEqual_Single(t *testing.T) {
	existing := []controller.TrafficMatchingListItem{{Value: "1.1.1.0/24"}}
	desired := []controller.TrafficMatchingListItem{{Value: "1.1.1.0/24"}}

	if !tmlItemsEqual(existing, desired) {
		t.Error("expected single items to match")
	}
}

// TestTMLItemsEqual_SingleMismatch tests single element mismatch.
func TestTMLItemsEqual_SingleMismatch(t *testing.T) {
	existing := []controller.TrafficMatchingListItem{{Value: "1.1.1.0/24"}}
	desired := []controller.TrafficMatchingListItem{{Value: "2.2.2.0/24"}}

	if tmlItemsEqual(existing, desired) {
		t.Error("expected single items to NOT match")
	}
}

// TestNewCloudflareProvider creates a provider and verifies defaults.
func TestNewCloudflareProvider(t *testing.T) {
	provider := NewCloudflareProvider("http://example.com/ipv4", "http://example.com/ipv6")

	if provider.IPv4URL != "http://example.com/ipv4" {
		t.Errorf("expected IPv4URL to be http://example.com/ipv4, got %s", provider.IPv4URL)
	}
	if provider.IPv6URL != "http://example.com/ipv6" {
		t.Errorf("expected IPv6URL to be http://example.com/ipv6, got %s", provider.IPv6URL)
	}
	if provider.HTTPClient == nil {
		t.Error("expected HTTPClient to be non-nil")
	}
}

// TestNewManager creates a manager and verifies it's properly initialized.
func TestNewManager(t *testing.T) {
	ctrl := testutil.NewMockController()
	log := zerolog.Nop()
	provider := NewCloudflareProvider("", "")

	mgr := NewManager(ctrl, []string{"site1"}, provider, log)
	if mgr.ctrl != ctrl {
		t.Error("expected manager ctrl to be the mock controller")
	}
	if len(mgr.sites) != 1 {
		t.Errorf("expected 1 site, got %d", len(mgr.sites))
	}
	if mgr.provider != provider {
		t.Error("expected manager provider to be the mock provider")
	}
}

// TestEnsureTML_Creates verifies that a new TML is created when none exists.
func TestEnsureTML_Creates(t *testing.T) {
	ctrl := testutil.NewMockController()
	log := zerolog.Nop()
	provider := NewCloudflareProvider("", "")

	mgr := NewManager(ctrl, []string{"test-site"}, provider, log)

	// No TMLs exist initially
	ctx := context.Background()

	// Call ensureTML with new TML name
	items := []controller.TrafficMatchingListItem{
		{Type: "SUBNET", Value: "1.1.1.0/24"},
		{Type: "SUBNET", Value: "2.2.2.0/24"},
	}
	_, err := mgr.ensureTML(ctx, "test-site", "test-tml", "IPV4_ADDRESSES", items)
	if err != nil {
		t.Fatalf("ensureTML failed: %v", err)
	}

	// Verify CreateTrafficMatchingList was called
	if got := ctrl.Calls("CreateTrafficMatchingList"); got != 1 {
		t.Errorf("CreateTrafficMatchingList calls: got %d, want 1", got)
	}
}

// TestEnsureTML_NoUpdateWhenUnchanged verifies that no update is made when TML items match.
func TestEnsureTML_NoUpdateWhenUnchanged(t *testing.T) {
	ctrl := testutil.NewMockController()
	log := zerolog.Nop()
	provider := NewCloudflareProvider("", "")

	mgr := NewManager(ctrl, []string{"test-site"}, provider, log)

	// Pre-populate a TML with the same items we'll try to sync
	ctx := context.Background()
	initialTML := controller.TrafficMatchingList{
		ID:    "tml-123",
		Name:  "test-tml",
		Type:  "IPV4_ADDRESSES",
		Items: []controller.TrafficMatchingListItem{{Value: "1.1.1.0/24"}, {Value: "2.2.2.0/24"}},
	}
	ctrl.SetTMLs("test-site", []controller.TrafficMatchingList{initialTML})

	// Call ensureTML with matching items
	items := []controller.TrafficMatchingListItem{
		{Type: "SUBNET", Value: "1.1.1.0/24"},
		{Type: "SUBNET", Value: "2.2.2.0/24"},
	}
	_, err := mgr.ensureTML(ctx, "test-site", "test-tml", "IPV4_ADDRESSES", items)
	if err != nil {
		t.Fatalf("ensureTML failed: %v", err)
	}

	// Verify no UpdateTrafficMatchingList was called
	if got := ctrl.Calls("UpdateTrafficMatchingList"); got != 0 {
		t.Errorf("UpdateTrafficMatchingList calls: got %d, want 0 (no update)", got)
	}
}

// TestEnsureTML_UpdatesWhenChanged verifies that UpdateTrafficMatchingList is called when items differ.
func TestEnsureTML_UpdatesWhenChanged(t *testing.T) {
	ctrl := testutil.NewMockController()
	log := zerolog.Nop()
	provider := NewCloudflareProvider("", "")

	mgr := NewManager(ctrl, []string{"test-site"}, provider, log)

	// Pre-populate a TML with different items
	ctx := context.Background()
	initialTML := controller.TrafficMatchingList{
		ID:    "tml-123",
		Name:  "test-tml",
		Type:  "IPV4_ADDRESSES",
		Items: []controller.TrafficMatchingListItem{{Value: "1.1.1.0/24"}},
	}
	ctrl.SetTMLs("test-site", []controller.TrafficMatchingList{initialTML})

	// Call ensureTML with different items
	items := []controller.TrafficMatchingListItem{
		{Type: "SUBNET", Value: "1.1.1.0/24"},
		{Type: "SUBNET", Value: "2.2.2.0/24"},
	}
	_, err := mgr.ensureTML(ctx, "test-site", "test-tml", "IPV4_ADDRESSES", items)
	if err != nil {
		t.Fatalf("ensureTML failed: %v", err)
	}

	// Verify UpdateTrafficMatchingList was called
	if got := ctrl.Calls("UpdateTrafficMatchingList"); got != 1 {
		t.Errorf("UpdateTrafficMatchingList calls: got %d, want 1", got)
	}
}

// TestEnsureAllowPolicy_Creates verifies that a new ALLOW policy is created when none exists.
func TestEnsureAllowPolicy_Creates(t *testing.T) {
	ctrl := testutil.NewMockController()
	log := zerolog.Nop()
	provider := NewCloudflareProvider("", "")

	mgr := NewManager(ctrl, []string{"test-site"}, provider, log)

	ctx := context.Background()
	pair := ZonePairConfig{
		SrcName:   "External",
		DstName:   "Internal",
		SrcZoneID: "zone-external",
		DstZoneID: "zone-internal",
	}

	// No policies exist initially
	_, err := mgr.ensureAllowPolicy(ctx, "test-site", pair, "tml-123", "", "", "IPV4", "test-allow-policy", nil)
	if err != nil {
		t.Fatalf("ensureAllowPolicy failed: %v", err)
	}

	// Verify CreateZonePolicy was called
	if got := ctrl.Calls("CreateZonePolicy"); got != 1 {
		t.Errorf("CreateZonePolicy calls: got %d, want 1", got)
	}
}

// TestEnsureAllowPolicy_TMLIDPopulated verifies that the created policy has TrafficMatchingListIDs set.
func TestEnsureAllowPolicy_TMLIDPopulated(t *testing.T) {
	ctrl := testutil.NewMockController()
	log := zerolog.Nop()
	provider := NewCloudflareProvider("", "")

	mgr := NewManager(ctrl, []string{"test-site"}, provider, log)

	ctx := context.Background()
	pair := ZonePairConfig{
		SrcName:   "External",
		DstName:   "Internal",
		SrcZoneID: "zone-external",
		DstZoneID: "zone-internal",
	}

	// Get the created policy from mock's policies list after CreateZonePolicy
	// We need to verify the policy struct passed to CreateZonePolicy has correct TML ID
	_, err := mgr.ensureAllowPolicy(ctx, "test-site", pair, "tml-123", "", "", "IPV4", "test-allow-policy", nil)
	if err != nil {
		t.Fatalf("ensureAllowPolicy failed: %v", err)
	}

	// Check the created policy
	policies, err := ctrl.ListZonePolicies(ctx, "test-site")
	if err != nil {
		t.Fatalf("ListZonePolicies failed: %v", err)
	}
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(policies))
	}

	policy := policies[0]
	if len(policy.TrafficMatchingListIDs) != 1 {
		t.Errorf("policy.TrafficMatchingListIDs: got len %d, want 1", len(policy.TrafficMatchingListIDs))
	}
	if policy.TrafficMatchingListIDs[0] != "tml-123" {
		t.Errorf("policy.TrafficMatchingListIDs[0]: got %q, want %q", policy.TrafficMatchingListIDs[0], "tml-123")
	}
	if policy.ConnectionStateFilter != nil {
		t.Errorf("policy.ConnectionStateFilter: got %v, want nil (All states)", policy.ConnectionStateFilter)
	}
}

// TestEnsureAllowPolicy_NoOpWhenCurrent verifies that no update is made when policy exists with correct TML.
func TestEnsureAllowPolicy_NoOpWhenCurrent(t *testing.T) {
	ctrl := testutil.NewMockController()
	log := zerolog.Nop()
	provider := NewCloudflareProvider("", "")

	mgr := NewManager(ctrl, []string{"test-site"}, provider, log)

	ctx := context.Background()
	pair := ZonePairConfig{
		SrcName:   "External",
		DstName:   "Internal",
		SrcZoneID: "zone-external",
		DstZoneID: "zone-internal",
	}

	// Pre-create a policy with the correct TML ID
	existingPolicy := controller.ZonePolicy{
		ID:                     "policy-123",
		Name:                   "test-allow-policy",
		Enabled:                true,
		Action:                 "ALLOW",
		SrcZone:                "zone-external",
		DstZone:                "zone-internal",
		IPVersion:              "IPV4",
		TrafficMatchingListIDs: []string{"tml-123"},
		ConnectionStateFilter:  nil,
	}
	ctrl.SetPolicies("test-site", []controller.ZonePolicy{existingPolicy})

	_, err := mgr.ensureAllowPolicy(ctx, "test-site", pair, "tml-123", "", "", "IPV4", "test-allow-policy", []controller.ZonePolicy{existingPolicy})
	if err != nil {
		t.Fatalf("ensureAllowPolicy failed: %v", err)
	}

	// Verify no UpdateZonePolicy was called
	if got := ctrl.Calls("UpdateZonePolicy"); got != 0 {
		t.Errorf("UpdateZonePolicy calls: got %d, want 0 (no update)", got)
	}
}

// TestEnsureAllowPolicy_UpdatesWhenTMLChanged verifies that UpdateZonePolicy is called when TML ID differs.
func TestEnsureAllowPolicy_UpdatesWhenTMLChanged(t *testing.T) {
	ctrl := testutil.NewMockController()
	log := zerolog.Nop()
	provider := NewCloudflareProvider("", "")

	mgr := NewManager(ctrl, []string{"test-site"}, provider, log)

	ctx := context.Background()
	pair := ZonePairConfig{
		SrcName:   "External",
		DstName:   "Internal",
		SrcZoneID: "zone-external",
		DstZoneID: "zone-internal",
	}

	// Pre-create a policy with wrong TML ID
	existingPolicy := controller.ZonePolicy{
		ID:                     "policy-123",
		Name:                   "test-allow-policy",
		Enabled:                true,
		Action:                 "ALLOW",
		SrcZone:                "zone-external",
		DstZone:                "zone-internal",
		IPVersion:              "IPV4",
		TrafficMatchingListIDs: []string{"old-tml-id"}, // Wrong TML
		ConnectionStateFilter:  nil,
	}
	ctrl.SetPolicies("test-site", []controller.ZonePolicy{existingPolicy})

	_, err := mgr.ensureAllowPolicy(ctx, "test-site", pair, "new-tml-id", "", "", "IPV4", "test-allow-policy", []controller.ZonePolicy{existingPolicy})
	if err != nil {
		t.Fatalf("ensureAllowPolicy failed: %v", err)
	}

	// Verify UpdateZonePolicy was called
	if got := ctrl.Calls("UpdateZonePolicy"); got != 1 {
		t.Errorf("UpdateZonePolicy calls: got %d, want 1", got)
	}

	// Verify the updated policy has the correct TML ID
	policies, err := ctrl.ListZonePolicies(ctx, "test-site")
	if err != nil {
		t.Fatalf("ListZonePolicies failed: %v", err)
	}
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(policies))
	}
	if policies[0].TrafficMatchingListIDs[0] != "new-tml-id" {
		t.Errorf("updated policy TML ID: got %q, want %q", policies[0].TrafficMatchingListIDs[0], "new-tml-id")
	}
}

// TestTMLItemsEqual_Match tests matching items in different order.
func TestTMLItemsEqual_Match(t *testing.T) {
	existing := []controller.TrafficMatchingListItem{
		{Value: "1.1.1.0/24"},
		{Value: "2.2.2.0/24"},
	}
	desired := []controller.TrafficMatchingListItem{
		{Value: "2.2.2.0/24"},
		{Value: "1.1.1.0/24"},
	}

	if !tmlItemsEqual(existing, desired) {
		t.Error("expected items to match (different order)")
	}
}

// TestEnsureTML_Creates_PortTML verifies a PORTS TML is created correctly.
func TestEnsureTML_Creates_PortTML(t *testing.T) {
	ctrl := testutil.NewMockController()
	log := zerolog.Nop()
	provider := NewCloudflareProvider("", "")

	mgr := NewManager(ctrl, []string{"test-site"}, provider, log)
	ctx := context.Background()

	portItems := []controller.TrafficMatchingListItem{
		{Type: "PORT_NUMBER", Value: "80"},
		{Type: "PORT_NUMBER", Value: "443"},
	}
	tml, err := mgr.ensureTML(ctx, "test-site", "test-ports-tml", "PORTS", portItems)
	if err != nil {
		t.Fatalf("ensureTML failed: %v", err)
	}
	if tml.ID == "" {
		t.Error("expected non-empty TML ID")
	}
	if ctrl.Calls("CreateTrafficMatchingList") != 1 {
		t.Errorf("CreateTrafficMatchingList calls: got %d, want 1", ctrl.Calls("CreateTrafficMatchingList"))
	}
}

// TestEnsureAllowPolicy_WithSrcDstPorts_Creates verifies port TML IDs are set on the created policy.
func TestEnsureAllowPolicy_WithSrcDstPorts_Creates(t *testing.T) {
	ctrl := testutil.NewMockController()
	log := zerolog.Nop()
	provider := NewCloudflareProvider("", "")

	mgr := NewManager(ctrl, []string{"test-site"}, provider, log)
	ctx := context.Background()

	pair := ZonePairConfig{
		SrcName:   "External",
		DstName:   "Internal",
		SrcZoneID: "zone-external",
		DstZoneID: "zone-internal",
	}

	_, err := mgr.ensureAllowPolicy(ctx, "test-site", pair, "tml-ip-123", "tml-src-port-1", "tml-dst-port-2", "IPV4", "test-allow-policy", nil)
	if err != nil {
		t.Fatalf("ensureAllowPolicy failed: %v", err)
	}

	policies, err := ctrl.ListZonePolicies(ctx, "test-site")
	if err != nil {
		t.Fatalf("ListZonePolicies failed: %v", err)
	}
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(policies))
	}
	if policies[0].SrcPortTMLID != "tml-src-port-1" {
		t.Errorf("SrcPortTMLID: got %q, want %q", policies[0].SrcPortTMLID, "tml-src-port-1")
	}
	if policies[0].DstPortTMLID != "tml-dst-port-2" {
		t.Errorf("DstPortTMLID: got %q, want %q", policies[0].DstPortTMLID, "tml-dst-port-2")
	}
}

// TestEnsureAllowPolicy_WithPorts_NoOpWhenCurrent verifies no update when port TML IDs match.
func TestEnsureAllowPolicy_WithPorts_NoOpWhenCurrent(t *testing.T) {
	ctrl := testutil.NewMockController()
	log := zerolog.Nop()
	provider := NewCloudflareProvider("", "")

	mgr := NewManager(ctrl, []string{"test-site"}, provider, log)
	ctx := context.Background()

	pair := ZonePairConfig{
		SrcName:   "External",
		DstName:   "Internal",
		SrcZoneID: "zone-external",
		DstZoneID: "zone-internal",
	}

	existingPolicy := controller.ZonePolicy{
		ID:                     "policy-123",
		Name:                   "test-allow-policy",
		Enabled:                true,
		Action:                 "ALLOW",
		SrcZone:                "zone-external",
		DstZone:                "zone-internal",
		IPVersion:              "IPV4",
		TrafficMatchingListIDs: []string{"tml-ip-123"},
		SrcPortTMLID:           "tml-src-port-1",
		DstPortTMLID:           "tml-dst-port-2",
	}
	ctrl.SetPolicies("test-site", []controller.ZonePolicy{existingPolicy})

	_, err := mgr.ensureAllowPolicy(ctx, "test-site", pair, "tml-ip-123", "tml-src-port-1", "tml-dst-port-2", "IPV4", "test-allow-policy", []controller.ZonePolicy{existingPolicy})
	if err != nil {
		t.Fatalf("ensureAllowPolicy failed: %v", err)
	}

	if got := ctrl.Calls("UpdateZonePolicy"); got != 0 {
		t.Errorf("UpdateZonePolicy calls: got %d, want 0 (no update)", got)
	}
}

// TestSyncSite_OrphanPolicy_IsDeleted verifies that a bouncer-managed policy whose
// zone pair has been removed from config is deleted during the orphan sweep.
func TestSyncSite_OrphanPolicy_IsDeleted(t *testing.T) {
	ctrl := testutil.NewMockController()
	log := zerolog.Nop()
	provider := NewCloudflareProvider("", "")
	mgr := NewManager(ctrl, []string{"test-site"}, provider, log)
	ctx := context.Background()

	// Pre-populate IP TMLs so ensureTML finds them without creating new ones.
	ctrl.SetTMLs("test-site", []controller.TrafficMatchingList{
		{ID: "tml-v4", Name: TMLNameV4, Type: "IPV4_ADDRESSES", Items: []controller.TrafficMatchingListItem{{Value: "1.1.1.0/24"}}},
		{ID: "tml-v6", Name: TMLNameV6, Type: "IPV6_ADDRESSES", Items: []controller.TrafficMatchingListItem{{Value: "2606:4700::/32"}}},
	})

	// Orphaned policy: was created when External→Dmz was configured, but that pair is now removed.
	orphan := controller.ZonePolicy{
		ID:                     "orphan-v4-id",
		Name:                   "crowdsec-whitelist-cloudflare-External-Dmz-v4",
		Description:            "Managed by cs-unifi-bouncer-pro. Cloudflare whitelist. Do not edit manually.",
		Action:                 "ALLOW",
		Enabled:                true,
		SrcZone:                "zone-external",
		DstZone:                "zone-dmz",
		IPVersion:              "IPV4",
		TrafficMatchingListIDs: []string{"tml-v4"},
	}
	ctrl.SetPolicies("test-site", []controller.ZonePolicy{orphan})

	// Sync with no zone pairs (zone pair removed from config).
	err := mgr.syncSite(ctx, "test-site", []string{"1.1.1.0/24"}, []string{"2606:4700::/32"}, nil)
	if err != nil {
		t.Fatalf("syncSite failed: %v", err)
	}

	if got := ctrl.Calls("DeleteZonePolicy"); got != 1 {
		t.Errorf("DeleteZonePolicy calls: got %d, want 1 (orphan must be deleted)", got)
	}
	policies, err := ctrl.ListZonePolicies(ctx, "test-site")
	if err != nil {
		t.Fatalf("ListZonePolicies failed: %v", err)
	}
	if len(policies) != 0 {
		t.Errorf("expected 0 policies after orphan sweep, got %d", len(policies))
	}
}

// TestSyncSite_DuplicateNamedPolicy_OldOrphanDeleted verifies that when two policies
// share the same name but only one is actively managed (by ID), the unmanaged duplicate
// is deleted. This is the ID-based tracking fix for the orphan cleanup bug.
func TestSyncSite_DuplicateNamedPolicy_OldOrphanDeleted(t *testing.T) {
	ctrl := testutil.NewMockController()
	log := zerolog.Nop()
	provider := NewCloudflareProvider("", "")
	mgr := NewManager(ctrl, []string{"test-site"}, provider, log)
	ctx := context.Background()

	ctrl.SetTMLs("test-site", []controller.TrafficMatchingList{
		{ID: "tml-v4", Name: TMLNameV4, Type: "IPV4_ADDRESSES", Items: []controller.TrafficMatchingListItem{{Value: "1.1.1.0/24"}}},
		{ID: "tml-v6", Name: TMLNameV6, Type: "IPV6_ADDRESSES", Items: []controller.TrafficMatchingListItem{{Value: "2606:4700::/32"}}},
	})

	const policyName = "crowdsec-whitelist-cloudflare-External-Dmz-v4"
	const managedDesc = "Managed by cs-unifi-bouncer-pro. Cloudflare whitelist. Do not edit manually."

	// Simulate two policies with the same name: the active managed one (found first
	// by ensureAllowPolicy) and an old stale duplicate with a different ID.
	active := controller.ZonePolicy{
		ID:                     "active-id",
		Name:                   policyName,
		Description:            managedDesc,
		Action:                 "ALLOW",
		AllowReturnTraffic:     true,
		Enabled:                true,
		SrcZone:                "zone-external",
		DstZone:                "zone-dmz",
		IPVersion:              "IPV4",
		TrafficMatchingListIDs: []string{"tml-v4"},
	}
	stale := controller.ZonePolicy{
		ID:                     "stale-id",
		Name:                   policyName,
		Description:            managedDesc,
		Action:                 "ALLOW",
		AllowReturnTraffic:     true,
		Enabled:                true,
		SrcZone:                "zone-external",
		DstZone:                "zone-dmz",
		IPVersion:              "IPV4",
		TrafficMatchingListIDs: []string{"tml-v4"},
	}
	ctrl.SetPolicies("test-site", []controller.ZonePolicy{active, stale})

	pair := ZonePairConfig{
		SrcName:   "External",
		DstName:   "Dmz",
		SrcZoneID: "zone-external",
		DstZoneID: "zone-dmz",
	}
	err := mgr.syncSite(ctx, "test-site", []string{"1.1.1.0/24"}, []string{"2606:4700::/32"}, []ZonePairConfig{pair})
	if err != nil {
		t.Fatalf("syncSite failed: %v", err)
	}

	// The stale duplicate must be deleted; the active policy must be kept.
	if got := ctrl.Calls("DeleteZonePolicy"); got != 1 {
		t.Errorf("DeleteZonePolicy calls: got %d, want 1 (stale duplicate must be deleted)", got)
	}
	policies, err := ctrl.ListZonePolicies(ctx, "test-site")
	if err != nil {
		t.Fatalf("ListZonePolicies failed: %v", err)
	}
	// After orphan sweep, only one policy (the active one) should remain.
	// The mock's DeleteZonePolicy removes by ID, so active-id should still be present.
	found := false
	for _, p := range policies {
		if p.ID == "active-id" {
			found = true
		}
		if p.ID == "stale-id" {
			t.Errorf("stale policy (stale-id) was not deleted by orphan sweep")
		}
	}
	if !found {
		t.Errorf("active policy (active-id) was incorrectly deleted")
	}
}

// TestSyncSite_ReturnMirror_KeptForManagedPolicy verifies that (Return) mirror policies
// auto-created by UniFi are preserved for managed forward policies and deleted for orphans.
func TestSyncSite_ReturnMirror_KeptForManagedPolicy(t *testing.T) {
	ctrl := testutil.NewMockController()
	log := zerolog.Nop()
	provider := NewCloudflareProvider("", "")
	mgr := NewManager(ctrl, []string{"test-site"}, provider, log)
	ctx := context.Background()

	ctrl.SetTMLs("test-site", []controller.TrafficMatchingList{
		{ID: "tml-v4", Name: TMLNameV4, Type: "IPV4_ADDRESSES", Items: []controller.TrafficMatchingListItem{{Value: "1.1.1.0/24"}}},
		{ID: "tml-v6", Name: TMLNameV6, Type: "IPV6_ADDRESSES", Items: []controller.TrafficMatchingListItem{{Value: "2606:4700::/32"}}},
	})

	const managedDesc = "Managed by cs-unifi-bouncer-pro. Cloudflare whitelist. Do not edit manually."

	// Active managed policy + its UniFi-auto-created Return mirror.
	active := controller.ZonePolicy{
		ID: "active-id", Name: "crowdsec-whitelist-cloudflare-External-Dmz-v4",
		Description: managedDesc, Action: "ALLOW", AllowReturnTraffic: true, Enabled: true,
		SrcZone: "zone-external", DstZone: "zone-dmz", IPVersion: "IPV4",
		TrafficMatchingListIDs: []string{"tml-v4"},
	}
	activeReturn := controller.ZonePolicy{
		ID: "active-return-id", Name: "crowdsec-whitelist-cloudflare-External-Dmz-v4 (Return)",
		Action: "ALLOW", Enabled: true, Predefined: true,
		SrcZone: "zone-dmz", DstZone: "zone-external", IPVersion: "IPV4",
	}
	// Orphaned Return mirror for a policy that is no longer in config.
	orphanReturn := controller.ZonePolicy{
		ID: "orphan-return-id", Name: "crowdsec-whitelist-cloudflare-External-Old-v4 (Return)",
		Action: "ALLOW", Enabled: true, Predefined: true,
		SrcZone: "zone-old", DstZone: "zone-external", IPVersion: "IPV4",
	}
	ctrl.SetPolicies("test-site", []controller.ZonePolicy{active, activeReturn, orphanReturn})

	pair := ZonePairConfig{SrcName: "External", DstName: "Dmz", SrcZoneID: "zone-external", DstZoneID: "zone-dmz"}
	err := mgr.syncSite(ctx, "test-site", []string{"1.1.1.0/24"}, []string{"2606:4700::/32"}, []ZonePairConfig{pair})
	if err != nil {
		t.Fatalf("syncSite failed: %v", err)
	}

	// Only the orphaned Return mirror should be deleted; the active Return mirror kept.
	if got := ctrl.Calls("DeleteZonePolicy"); got != 1 {
		t.Errorf("DeleteZonePolicy calls: got %d, want 1 (only orphan Return mirror deleted)", got)
	}
	policies, err := ctrl.ListZonePolicies(ctx, "test-site")
	if err != nil {
		t.Fatalf("ListZonePolicies failed: %v", err)
	}
	ids := make(map[string]bool)
	for _, p := range policies {
		ids[p.ID] = true
	}
	if !ids["active-return-id"] {
		t.Error("active Return mirror was incorrectly deleted")
	}
	if ids["orphan-return-id"] {
		t.Error("orphaned Return mirror was not deleted")
	}
}

// TestEnsureAllowPolicy_WithPorts_UpdatesWhenChanged verifies that when portFilter
// IDs change on an existing policy, the policy is deleted and recreated (not PUT),
// because the UniFi PUT endpoint does not accept portFilter in the request body.
func TestEnsureAllowPolicy_WithPorts_UpdatesWhenChanged(t *testing.T) {
	ctrl := testutil.NewMockController()
	log := zerolog.Nop()
	provider := NewCloudflareProvider("", "")

	mgr := NewManager(ctrl, []string{"test-site"}, provider, log)
	ctx := context.Background()

	pair := ZonePairConfig{
		SrcName:   "External",
		DstName:   "Internal",
		SrcZoneID: "zone-external",
		DstZoneID: "zone-internal",
	}

	existingPolicy := controller.ZonePolicy{
		ID:                     "policy-123",
		Name:                   "test-allow-policy",
		Enabled:                true,
		Action:                 "ALLOW",
		SrcZone:                "zone-external",
		DstZone:                "zone-internal",
		IPVersion:              "IPV4",
		TrafficMatchingListIDs: []string{"tml-ip-123"},
		SrcPortTMLID:           "old-src-port-tml",
		DstPortTMLID:           "",
	}
	ctrl.SetPolicies("test-site", []controller.ZonePolicy{existingPolicy})

	_, err := mgr.ensureAllowPolicy(ctx, "test-site", pair, "tml-ip-123", "new-src-port-tml", "new-dst-port-tml", "IPV4", "test-allow-policy", []controller.ZonePolicy{existingPolicy})
	if err != nil {
		t.Fatalf("ensureAllowPolicy failed: %v", err)
	}

	// portFilter changed → must use delete+recreate, not PUT
	if got := ctrl.Calls("UpdateZonePolicy"); got != 0 {
		t.Errorf("UpdateZonePolicy calls: got %d, want 0 (portFilter change requires delete+recreate, not PUT)", got)
	}
	if got := ctrl.Calls("DeleteZonePolicy"); got != 1 {
		t.Errorf("DeleteZonePolicy calls: got %d, want 1", got)
	}
	if got := ctrl.Calls("CreateZonePolicy"); got != 1 {
		t.Errorf("CreateZonePolicy calls: got %d, want 1", got)
	}
	policies, err := ctrl.ListZonePolicies(ctx, "test-site")
	if err != nil {
		t.Fatalf("ListZonePolicies failed: %v", err)
	}
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy after recreate, got %d", len(policies))
	}
	if policies[0].SrcPortTMLID != "new-src-port-tml" {
		t.Errorf("recreated SrcPortTMLID: got %q, want %q", policies[0].SrcPortTMLID, "new-src-port-tml")
	}
	if policies[0].DstPortTMLID != "new-dst-port-tml" {
		t.Errorf("recreated DstPortTMLID: got %q, want %q", policies[0].DstPortTMLID, "new-dst-port-tml")
	}
}

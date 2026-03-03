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
	err := mgr.ensureAllowPolicy(ctx, "test-site", pair, "tml-123", "", "", "IPV4", "test-allow-policy", nil)
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
	err := mgr.ensureAllowPolicy(ctx, "test-site", pair, "tml-123", "", "", "IPV4", "test-allow-policy", nil)
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

	err := mgr.ensureAllowPolicy(ctx, "test-site", pair, "tml-123", "", "", "IPV4", "test-allow-policy", []controller.ZonePolicy{existingPolicy})
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

	err := mgr.ensureAllowPolicy(ctx, "test-site", pair, "new-tml-id", "", "", "IPV4", "test-allow-policy", []controller.ZonePolicy{existingPolicy})
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

	err := mgr.ensureAllowPolicy(ctx, "test-site", pair, "tml-ip-123", "tml-src-port-1", "tml-dst-port-2", "IPV4", "test-allow-policy", nil)
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

	err := mgr.ensureAllowPolicy(ctx, "test-site", pair, "tml-ip-123", "tml-src-port-1", "tml-dst-port-2", "IPV4", "test-allow-policy", []controller.ZonePolicy{existingPolicy})
	if err != nil {
		t.Fatalf("ensureAllowPolicy failed: %v", err)
	}

	if got := ctrl.Calls("UpdateZonePolicy"); got != 0 {
		t.Errorf("UpdateZonePolicy calls: got %d, want 0 (no update)", got)
	}
}

// TestEnsureAllowPolicy_WithPorts_UpdatesWhenChanged verifies update when port TML IDs differ.
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

	err := mgr.ensureAllowPolicy(ctx, "test-site", pair, "tml-ip-123", "new-src-port-tml", "new-dst-port-tml", "IPV4", "test-allow-policy", []controller.ZonePolicy{existingPolicy})
	if err != nil {
		t.Fatalf("ensureAllowPolicy failed: %v", err)
	}

	if got := ctrl.Calls("UpdateZonePolicy"); got != 1 {
		t.Errorf("UpdateZonePolicy calls: got %d, want 1", got)
	}
	policies, err := ctrl.ListZonePolicies(ctx, "test-site")
	if err != nil {
		t.Fatalf("ListZonePolicies failed: %v", err)
	}
	if policies[0].SrcPortTMLID != "new-src-port-tml" {
		t.Errorf("updated SrcPortTMLID: got %q, want %q", policies[0].SrcPortTMLID, "new-src-port-tml")
	}
	if policies[0].DstPortTMLID != "new-dst-port-tml" {
		t.Errorf("updated DstPortTMLID: got %q, want %q", policies[0].DstPortTMLID, "new-dst-port-tml")
	}
}

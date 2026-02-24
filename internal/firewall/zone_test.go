package firewall

import (
	"context"
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/rs/zerolog"
)

// zoneTestNamer returns a Namer using the default templates for zone tests.
func zoneTestNamer(t *testing.T) *Namer {
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

// newTestZoneManager returns a ZoneManager with a single wan->lan zone pair.
func newTestZoneManager(ctrl controller.Controller, store storage.Store, namer *Namer) *ZoneManager {
	return NewZoneManager(ZoneConfig{
		ZonePairs:   []config.ZonePair{{Src: "wan", Dst: "lan"}},
		Description: "test",
	}, namer, ctrl, store, zerolog.Nop())
}

// ensuredZoneV4Shard creates and ensures a v4 ShardManager for zone tests.
func ensuredZoneV4Shard(t *testing.T, ctrl controller.Controller, store storage.Store) *ShardManager {
	t.Helper()
	namer := zoneTestNamer(t)
	sm := NewShardManager(testSite, false, 5, namer, ctrl, store, zerolog.Nop(), 0, nil, false, "zone")
	if err := sm.EnsureShards(context.Background()); err != nil {
		t.Fatalf("EnsureShards (v4): %v", err)
	}
	return sm
}

// ensuredZoneV6Shard creates and ensures a v6 ShardManager for zone tests.
func ensuredZoneV6Shard(t *testing.T, ctrl controller.Controller, store storage.Store) *ShardManager {
	t.Helper()
	namer := zoneTestNamer(t)
	sm := NewShardManager(testSite, true, 5, namer, ctrl, store, zerolog.Nop(), 0, nil, false, "zone")
	if err := sm.EnsureShards(context.Background()); err != nil {
		t.Fatalf("EnsureShards (v6): %v", err)
	}
	return sm
}

// TestZoneManager_EnsurePolicies_Create verifies that when no policies exist,
// EnsurePolicies calls CreateZonePolicy for each shard and zone pair.
func TestZoneManager_EnsurePolicies_Create(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := testutil.NewMockStore()
	namer := zoneTestNamer(t)

	v4 := ensuredZoneV4Shard(t, ctrl, store)
	zm := newTestZoneManager(ctrl, store, namer)

	if err := zm.EnsurePolicies(context.Background(), testSite, v4, nil); err != nil {
		t.Fatalf("EnsurePolicies: %v", err)
	}

	// One shard and one zone pair → one policy created.
	if got := ctrl.Calls("CreateZonePolicy"); got != 1 {
		t.Errorf("CreateZonePolicy calls: got %d, want 1", got)
	}
}

// TestZoneManager_EnsurePolicies_Idempotent verifies that when the policy record
// is already in bbolt AND the corresponding policy exists in the API list,
// CreateZonePolicy is not called again.
func TestZoneManager_EnsurePolicies_Idempotent(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := testutil.NewMockStore()
	namer := zoneTestNamer(t)

	v4 := ensuredZoneV4Shard(t, ctrl, store)
	zm := newTestZoneManager(ctrl, store, namer)

	// First call — creates the policy.
	if err := zm.EnsurePolicies(context.Background(), testSite, v4, nil); err != nil {
		t.Fatalf("EnsurePolicies (first): %v", err)
	}

	firstCalls := ctrl.Calls("CreateZonePolicy")

	// Second call — policy is in bbolt and still exists in the API.
	if err := zm.EnsurePolicies(context.Background(), testSite, v4, nil); err != nil {
		t.Fatalf("EnsurePolicies (second): %v", err)
	}

	if got := ctrl.Calls("CreateZonePolicy"); got != firstCalls {
		t.Errorf("second EnsurePolicies: CreateZonePolicy went from %d to %d; want no new calls",
			firstCalls, ctrl.Calls("CreateZonePolicy"))
	}
}

// TestZoneManager_EnsurePolicies_MultiPair verifies that two zone pairs each
// cause a CreateZonePolicy call per shard (2 pairs × 1 shard = 2 calls).
func TestZoneManager_EnsurePolicies_MultiPair(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := testutil.NewMockStore()
	namer := zoneTestNamer(t)

	v4 := ensuredZoneV4Shard(t, ctrl, store)

	zm := NewZoneManager(ZoneConfig{
		ZonePairs: []config.ZonePair{
			{Src: "wan", Dst: "lan"},
			{Src: "wan", Dst: "iot"},
		},
		Description: "test",
	}, namer, ctrl, store, zerolog.Nop())

	if err := zm.EnsurePolicies(context.Background(), testSite, v4, nil); err != nil {
		t.Fatalf("EnsurePolicies: %v", err)
	}

	// Two zone pairs, one shard each → 2 CreateZonePolicy calls.
	if got := ctrl.Calls("CreateZonePolicy"); got != 2 {
		t.Errorf("CreateZonePolicy calls: got %d, want 2", got)
	}
}

// TestZoneManager_EnsurePolicies_IPv6 verifies that passing a v6 ShardManager
// causes CreateZonePolicy to be called with IPVersion="IPV6".
func TestZoneManager_EnsurePolicies_IPv6(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := testutil.NewMockStore()
	namer := zoneTestNamer(t)

	v4 := ensuredZoneV4Shard(t, ctrl, store)
	v6 := ensuredZoneV6Shard(t, ctrl, store)
	zm := newTestZoneManager(ctrl, store, namer)

	if err := zm.EnsurePolicies(context.Background(), testSite, v4, v6); err != nil {
		t.Fatalf("EnsurePolicies: %v", err)
	}

	// One v4 policy + one v6 policy.
	if got := ctrl.Calls("CreateZonePolicy"); got < 2 {
		t.Errorf("CreateZonePolicy calls: got %d, want >= 2 (v4 + v6)", got)
	}

	// Verify at least one policy has IPVersion=IPV6.
	policies, err := ctrl.ListZonePolicies(context.Background(), testSite)
	if err != nil {
		t.Fatal(err)
	}
	hasIPv6Policy := false
	for _, p := range policies {
		if p.IPVersion == "IPV6" {
			hasIPv6Policy = true
			break
		}
	}
	if !hasIPv6Policy {
		t.Error("no zone policy with IPVersion=IPV6 found; expected one for the v6 shard")
	}
}

// TestZoneManager_EnsurePolicies_RecreatesDeleted verifies that when a policy
// record exists in the store but is absent from the API, it is recreated.
func TestZoneManager_EnsurePolicies_RecreatesDeleted(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := testutil.NewMockStore()
	namer := zoneTestNamer(t)

	v4 := ensuredZoneV4Shard(t, ctrl, store)
	zm := newTestZoneManager(ctrl, store, namer)

	// First call — creates the policy.
	if err := zm.EnsurePolicies(context.Background(), testSite, v4, nil); err != nil {
		t.Fatalf("EnsurePolicies (first): %v", err)
	}

	firstCalls := ctrl.Calls("CreateZonePolicy")

	// Simulate the policy being deleted from UniFi.
	ctrl.SetPolicies(testSite, []controller.ZonePolicy{})

	// Second call — bbolt has the record but the API no longer has the policy.
	if err := zm.EnsurePolicies(context.Background(), testSite, v4, nil); err != nil {
		t.Fatalf("EnsurePolicies (second): %v", err)
	}

	if got := ctrl.Calls("CreateZonePolicy"); got <= firstCalls {
		t.Errorf("CreateZonePolicy calls: got %d, want > %d (policy should be recreated)", got, firstCalls)
	}
}

// TestZoneManager_EnsurePoliciesForShard_Create verifies that EnsurePoliciesForShard
// creates a policy for each zone pair for the given shard.
func TestZoneManager_EnsurePoliciesForShard_Create(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := testutil.NewMockStore()
	namer := zoneTestNamer(t)

	v4 := ensuredZoneV4Shard(t, ctrl, store)
	zm := newTestZoneManager(ctrl, store, namer)

	groupIDs := v4.GroupIDs()
	if len(groupIDs) == 0 {
		t.Fatal("expected at least one shard")
	}

	if err := zm.EnsurePoliciesForShard(context.Background(), testSite, groupIDs[0], false, 0); err != nil {
		t.Fatalf("EnsurePoliciesForShard: %v", err)
	}

	// One zone pair configured → one CreateZonePolicy call
	if got := ctrl.Calls("CreateZonePolicy"); got != 1 {
		t.Errorf("CreateZonePolicy calls: got %d, want 1", got)
	}
}

// TestZoneManager_EnsurePoliciesForShard_Idempotent verifies that calling
// EnsurePoliciesForShard twice does not create duplicate policies.
func TestZoneManager_EnsurePoliciesForShard_Idempotent(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := testutil.NewMockStore()
	namer := zoneTestNamer(t)

	v4 := ensuredZoneV4Shard(t, ctrl, store)
	zm := newTestZoneManager(ctrl, store, namer)

	groupIDs := v4.GroupIDs()
	if err := zm.EnsurePoliciesForShard(context.Background(), testSite, groupIDs[0], false, 0); err != nil {
		t.Fatalf("EnsurePoliciesForShard (first): %v", err)
	}
	firstCalls := ctrl.Calls("CreateZonePolicy")

	if err := zm.EnsurePoliciesForShard(context.Background(), testSite, groupIDs[0], false, 0); err != nil {
		t.Fatalf("EnsurePoliciesForShard (second): %v", err)
	}
	if got := ctrl.Calls("CreateZonePolicy"); got != firstCalls {
		t.Errorf("second EnsurePoliciesForShard: CreateZonePolicy went from %d to %d; want no new calls",
			firstCalls, ctrl.Calls("CreateZonePolicy"))
	}
}

// TestZoneManager_DeletePoliciesForShard verifies that DeletePoliciesForShard removes
// the policy and its bbolt record.
func TestZoneManager_DeletePoliciesForShard(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := testutil.NewMockStore()
	namer := zoneTestNamer(t)

	v4 := ensuredZoneV4Shard(t, ctrl, store)
	zm := newTestZoneManager(ctrl, store, namer)

	groupIDs := v4.GroupIDs()
	// Create first
	if err := zm.EnsurePoliciesForShard(context.Background(), testSite, groupIDs[0], false, 0); err != nil {
		t.Fatalf("EnsurePoliciesForShard: %v", err)
	}

	// Delete
	if err := zm.DeletePoliciesForShard(context.Background(), testSite, false, 0); err != nil {
		t.Fatalf("DeletePoliciesForShard: %v", err)
	}

	if got := ctrl.Calls("DeleteZonePolicy"); got != 1 {
		t.Errorf("DeleteZonePolicy calls: got %d, want 1", got)
	}
}

// TestZoneManager_DeletePoliciesForShard_NoOp verifies that DeletePoliciesForShard
// is a no-op when no policy record exists.
func TestZoneManager_DeletePoliciesForShard_NoOp(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := testutil.NewMockStore()
	namer := zoneTestNamer(t)

	zm := newTestZoneManager(ctrl, store, namer)

	// No policy was ever created
	if err := zm.DeletePoliciesForShard(context.Background(), testSite, false, 0); err != nil {
		t.Fatalf("DeletePoliciesForShard (no-op): %v", err)
	}
	if got := ctrl.Calls("DeleteZonePolicy"); got != 0 {
		t.Errorf("DeleteZonePolicy calls: got %d, want 0 (no-op)", got)
	}
}

// TestZoneManager_EnsurePolicies_ListsOnce verifies that EnsurePolicies calls
// ListZonePolicies exactly once regardless of the number of zone pairs or families.
func TestZoneManager_EnsurePolicies_ListsOnce(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := testutil.NewMockStore()
	namer := zoneTestNamer(t)

	v4 := ensuredZoneV4Shard(t, ctrl, store)
	v6 := ensuredZoneV6Shard(t, ctrl, store)

	zm := NewZoneManager(ZoneConfig{
		ZonePairs: []config.ZonePair{
			{Src: "wan", Dst: "lan"},
			{Src: "wan", Dst: "iot"},
		},
		Description: "test",
	}, namer, ctrl, store, zerolog.Nop())

	listsBefore := ctrl.Calls("ListZonePolicies")

	if err := zm.EnsurePolicies(context.Background(), testSite, v4, v6); err != nil {
		t.Fatalf("EnsurePolicies: %v", err)
	}

	// 2 pairs × 2 families = 4 ensurePoliciesForPair calls, but ListZonePolicies must be 1.
	if got := ctrl.Calls("ListZonePolicies") - listsBefore; got != 1 {
		t.Errorf("ListZonePolicies calls = %d, want 1", got)
	}
}

// TestZoneManager_Bootstrap_FailsWhenSiteMissing verifies that Bootstrap returns
// an error when GetSiteID fails (fail-fast site UUID resolution).
func TestZoneManager_Bootstrap_FailsWhenSiteMissing(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := testutil.NewMockStore()
	namer := zoneTestNamer(t)

	ctrl.SetError("GetSiteID", errTest("site not found"))

	zm := newTestZoneManager(ctrl, store, namer)
	err := zm.Bootstrap(context.Background(), []string{testSite})
	if err == nil {
		t.Fatal("Bootstrap: expected error when GetSiteID fails, got nil")
	}
}

// TestZoneManager_Bootstrap_FailsWhenZonesFail verifies that Bootstrap returns
// an error when DiscoverZones fails (fail-fast zone discovery).
func TestZoneManager_Bootstrap_FailsWhenZonesFail(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := testutil.NewMockStore()
	namer := zoneTestNamer(t)

	ctrl.SetError("DiscoverZones", errTest("zones unavailable"))

	zm := newTestZoneManager(ctrl, store, namer)
	err := zm.Bootstrap(context.Background(), []string{testSite})
	if err == nil {
		t.Fatal("Bootstrap: expected error when DiscoverZones fails, got nil")
	}
}

// TestZoneManager_EnsurePolicies_AlwaysHasTMLSourceFilter verifies that
// block policies are never created with "Any IP" source.
func TestZoneManager_EnsurePolicies_AlwaysHasTMLSourceFilter(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := testutil.NewMockStore()
	namer := zoneTestNamer(t)

	v4 := ensuredZoneV4Shard(t, ctrl, store)
	zm := newTestZoneManager(ctrl, store, namer)

	if err := zm.EnsurePolicies(context.Background(), testSite, v4, nil); err != nil {
		t.Fatalf("EnsurePolicies: %v", err)
	}

	// Get all created policies
	policies, err := ctrl.ListZonePolicies(context.Background(), testSite)
	if err != nil {
		t.Fatalf("ListZonePolicies: %v", err)
	}

	// Verify each policy has TrafficMatchingListIDs set correctly
	for i, p := range policies {
		if len(p.TrafficMatchingListIDs) != 1 {
			t.Errorf("policy[%d] (%s): len(TrafficMatchingListIDs) = %d, want 1",
				i, p.Name, len(p.TrafficMatchingListIDs))
		}
		if p.TrafficMatchingListIDs[0] == "" {
			t.Errorf("policy[%d] (%s): TrafficMatchingListIDs[0] is empty, want non-empty TML ID",
				i, p.Name)
		}
		if p.ConnectionStateFilter != nil {
			t.Errorf("policy[%d] (%s): ConnectionStateFilter = %v, want nil (All states)",
				i, p.Name, p.ConnectionStateFilter)
		}
	}
}

// TestZoneManager_EnsurePolicies_ReconcileFixesMissingTML verifies that
// existing policies missing a TML source filter are updated.
func TestZoneManager_EnsurePolicies_ReconcileFixesMissingTML(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := testutil.NewMockStore()
	namer := zoneTestNamer(t)

	v4 := ensuredZoneV4Shard(t, ctrl, store)
	zm := newTestZoneManager(ctrl, store, namer)

	// First call - creates policies with correct TML
	if err := zm.EnsurePolicies(context.Background(), testSite, v4, nil); err != nil {
		t.Fatalf("EnsurePolicies (first): %v", err)
	}

	// Get the created policy's ID
	policies, err := ctrl.ListZonePolicies(context.Background(), testSite)
	if err != nil {
		t.Fatalf("ListZonePolicies: %v", err)
	}
	if len(policies) == 0 {
		t.Fatal("no policies created")
	}
	policyID := policies[0].ID

	// Simulate a policy being corrupted (missing TML ID)
	// This simulates a policy that was created before TML enforcement was added
	corruptedPolicy := controller.ZonePolicy{
		ID:                     policyID,
		Name:                   policies[0].Name,
		Enabled:                true,
		Action:                 "BLOCK",
		Description:            policies[0].Description,
		SrcZone:                policies[0].SrcZone,
		DstZone:                policies[0].DstZone,
		IPVersion:              policies[0].IPVersion,
		TrafficMatchingListIDs: []string{}, // Missing TML - this is the bug we're testing
		ConnectionStateFilter:  nil,
		LoggingEnabled:         policies[0].LoggingEnabled,
	}
	ctrl.SetPolicies(testSite, []controller.ZonePolicy{corruptedPolicy})

	// Second call - should detect missing TML and call UpdateZonePolicy
	if err := zm.EnsurePolicies(context.Background(), testSite, v4, nil); err != nil {
		t.Fatalf("EnsurePolicies (second): %v", err)
	}

	// Verify UpdateZonePolicy was called to fix the policy
	if got := ctrl.Calls("UpdateZonePolicy"); got != 1 {
		t.Errorf("UpdateZonePolicy calls: got %d, want 1 (policy should be updated)", got)
	}

	// Verify the updated policy has the correct TML ID
	policies, err = ctrl.ListZonePolicies(context.Background(), testSite)
	if err != nil {
		t.Fatalf("ListZonePolicies: %v", err)
	}
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(policies))
	}
	if len(policies[0].TrafficMatchingListIDs) != 1 {
		t.Errorf("updated policy: len(TrafficMatchingListIDs) = %d, want 1",
			len(policies[0].TrafficMatchingListIDs))
	}
	if policies[0].TrafficMatchingListIDs[0] == "" {
		t.Error("updated policy: TrafficMatchingListIDs[0] is empty, want non-empty TML ID")
	}
}

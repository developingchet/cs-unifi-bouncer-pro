package firewall

import (
	"context"
	"strings"
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
	// With lazy creation, add a dummy IP to trigger shard allocation, then flush
	// to transition Pending→Active (giving the shard a real UniFi ID), then remove.
	if _, _, err := sm.Add(context.Background(), "10.0.0.1"); err != nil {
		t.Fatalf("Add dummy IP: %v", err)
	}
	if err := sm.FlushDirty(context.Background()); err != nil {
		t.Fatalf("FlushDirty: %v", err)
	}
	if _, err := sm.Remove(context.Background(), "10.0.0.1"); err != nil {
		t.Fatalf("Remove dummy IP: %v", err)
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
	// With lazy creation, add a dummy IP to trigger shard allocation, then flush
	// to transition Pending→Active (giving the shard a real UniFi ID), then remove.
	if _, _, err := sm.Add(context.Background(), "2001:db8::1"); err != nil {
		t.Fatalf("Add dummy IP: %v", err)
	}
	if err := sm.FlushDirty(context.Background()); err != nil {
		t.Fatalf("FlushDirty: %v", err)
	}
	if _, err := sm.Remove(context.Background(), "2001:db8::1"); err != nil {
		t.Fatalf("Remove dummy IP: %v", err)
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

	if err := zm.Bootstrap(context.Background(), []string{testSite}); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
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

	if err := zm.Bootstrap(context.Background(), []string{testSite}); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
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

	if err := zm.Bootstrap(context.Background(), []string{testSite}); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
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

	if err := zm.Bootstrap(context.Background(), []string{testSite}); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
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

	if err := zm.Bootstrap(context.Background(), []string{testSite}); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
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

	if err := zm.Bootstrap(context.Background(), []string{testSite}); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
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

	if err := zm.Bootstrap(context.Background(), []string{testSite}); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
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

	if err := zm.Bootstrap(context.Background(), []string{testSite}); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
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

	if err := zm.Bootstrap(context.Background(), []string{testSite}); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
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

// TestZoneManager_EnsurePolicies_DstIPTML verifies that when a zone pair has
// DstIPs configured, the correct IP TML is created and referenced in the policy.
func TestZoneManager_EnsurePolicies_DstIPTML(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := testutil.NewMockStore()
	namer := zoneTestNamer(t)

	v4 := ensuredZoneV4Shard(t, ctrl, store)

	zm := NewZoneManager(ZoneConfig{
		ZonePairs: []config.ZonePair{
			{Src: "wan", Dst: "lan", DstIPs: []string{"10.0.1.0/24", "10.0.2.0/24"}},
		},
		Description: "test",
	}, namer, ctrl, store, zerolog.Nop())

	if err := zm.Bootstrap(context.Background(), []string{testSite}); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if err := zm.EnsurePolicies(context.Background(), testSite, v4, nil); err != nil {
		t.Fatalf("EnsurePolicies: %v", err)
	}

	// A dst IP TML should have been created.
	if got := ctrl.Calls("CreateTrafficMatchingList"); got < 1 {
		t.Errorf("CreateTrafficMatchingList calls: got %d, want >= 1", got)
	}

	// The created TML should be of type IPV4_ADDRESSES.
	tmls, err := ctrl.ListTrafficMatchingLists(context.Background(), testSite)
	if err != nil {
		t.Fatalf("ListTrafficMatchingLists: %v", err)
	}
	var dstIPTML *controller.TrafficMatchingList
	for i := range tmls {
		if strings.HasPrefix(tmls[i].Name, "crowdsec-dstips-v4-") {
			dstIPTML = &tmls[i]
			break
		}
	}
	if dstIPTML == nil {
		t.Fatal("expected a crowdsec-dstips-v4-* TML to be created")
	}
	if dstIPTML.Type != "IPV4_ADDRESSES" {
		t.Errorf("TML type = %q, want IPV4_ADDRESSES", dstIPTML.Type)
	}
	if len(dstIPTML.Items) != 2 {
		t.Errorf("TML items count = %d, want 2", len(dstIPTML.Items))
	}

	// The created zone policy should reference the dst IP TML.
	policies, err := ctrl.ListZonePolicies(context.Background(), testSite)
	if err != nil {
		t.Fatalf("ListZonePolicies: %v", err)
	}
	if len(policies) == 0 {
		t.Fatal("no policies created")
	}
	if policies[0].DstIPTMLID != dstIPTML.ID {
		t.Errorf("policy DstIPTMLID = %q, want %q", policies[0].DstIPTMLID, dstIPTML.ID)
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

	if err := zm.Bootstrap(context.Background(), []string{testSite}); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
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

	if err := zm.Bootstrap(context.Background(), []string{testSite}); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
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

// TestZoneManager_EnsurePolicies_APIOrphan_DeletedWithoutBboltRecord verifies that
// EnsurePolicies removes a block policy that bears the managed description and is
// not in the expected set, even when bbolt has no record of it. This covers the
// "wiped bbolt", "mode switch", and "prior installation" scenarios.
func TestZoneManager_EnsurePolicies_APIOrphan_DeletedWithoutBboltRecord(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := testutil.NewMockStore() // empty bbolt — no record of the orphan
	namer := zoneTestNamer(t)

	v4 := ensuredZoneV4Shard(t, ctrl, store)
	zm := newTestZoneManager(ctrl, store, namer) // wan→lan only

	if err := zm.Bootstrap(context.Background(), []string{testSite}); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	// Pre-populate the API with an orphaned policy for a zone pair (wan→dmz) that
	// is NOT in the current config, bearing our managed description. bbolt has no
	// record of it — simulating a wiped db or a prior install's leftover.
	orphan := controller.ZonePolicy{
		ID:                     "orphan-api-id",
		Name:                   "crowdsec-policy-wan-dmz-v4-0",
		Description:            "test", // matches zm.cfg.Description
		Action:                 "BLOCK",
		Enabled:                true,
		SrcZone:                "wan",
		DstZone:                "dmz",
		IPVersion:              "IPV4",
		TrafficMatchingListIDs: []string{"some-group-id"},
	}
	ctrl.SetPolicies(testSite, []controller.ZonePolicy{orphan})

	if err := zm.EnsurePolicies(context.Background(), testSite, v4, nil); err != nil {
		t.Fatalf("EnsurePolicies: %v", err)
	}

	// The orphaned policy must have been deleted by the API-level sweep.
	if got := ctrl.Calls("DeleteZonePolicy"); got != 1 {
		t.Errorf("DeleteZonePolicy calls: got %d, want 1 (API orphan must be deleted)", got)
	}
	policies, err := ctrl.ListZonePolicies(context.Background(), testSite)
	if err != nil {
		t.Fatalf("ListZonePolicies: %v", err)
	}
	for _, p := range policies {
		if p.ID == "orphan-api-id" {
			t.Error("orphaned policy was not removed from the API")
		}
	}
}

// TestZoneManager_EnsurePolicies_UnmanagedAPIPolicy_Preserved verifies that a
// policy with a description that does NOT match the managed description is left
// alone by the API-level orphan sweep.
func TestZoneManager_EnsurePolicies_UnmanagedAPIPolicy_Preserved(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := testutil.NewMockStore()
	namer := zoneTestNamer(t)

	v4 := ensuredZoneV4Shard(t, ctrl, store)
	zm := newTestZoneManager(ctrl, store, namer)

	if err := zm.Bootstrap(context.Background(), []string{testSite}); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	// A policy that looks like it could be ours by name but has a different
	// description — must not be touched.
	userPolicy := controller.ZonePolicy{
		ID:          "user-policy-id",
		Name:        "crowdsec-policy-wan-dmz-v4-0",
		Description: "created by hand",
		Action:      "BLOCK",
		Enabled:     true,
	}
	ctrl.SetPolicies(testSite, []controller.ZonePolicy{userPolicy})

	if err := zm.EnsurePolicies(context.Background(), testSite, v4, nil); err != nil {
		t.Fatalf("EnsurePolicies: %v", err)
	}

	if got := ctrl.Calls("DeleteZonePolicy"); got != 0 {
		t.Errorf("DeleteZonePolicy calls: got %d, want 0 (unmanaged policy must be preserved)", got)
	}
}

// TestZoneManager_EnsurePoliciesForShard_DstIPTML_V4Only verifies the family-agnostic
// dst IP behaviour in the EnsurePoliciesForShard path: when only v4 destination IPs
// are configured, both the v4 and v6 new-shard block policies must carry the v4 TML ID.
// This exercises the pickDstIPTML helper in the shard-overflow activation path.
func TestZoneManager_EnsurePoliciesForShard_DstIPTML_V4Only(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := testutil.NewMockStore()
	namer := zoneTestNamer(t)

	v4 := ensuredZoneV4Shard(t, ctrl, store)
	v6 := ensuredZoneV6Shard(t, ctrl, store)

	zm := NewZoneManager(ZoneConfig{
		ZonePairs: []config.ZonePair{
			{Src: "wan", Dst: "lan", DstIPs: []string{"10.0.5.251"}}, // v4-only dst IP
		},
		Description: "test",
	}, namer, ctrl, store, zerolog.Nop())

	if err := zm.Bootstrap(context.Background(), []string{testSite}); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	v4GroupIDs := v4.GroupIDs()
	if len(v4GroupIDs) == 0 {
		t.Fatal("expected at least one v4 shard")
	}
	v6GroupIDs := v6.GroupIDs()
	if len(v6GroupIDs) == 0 {
		t.Fatal("expected at least one v6 shard")
	}

	if err := zm.EnsurePoliciesForShard(context.Background(), testSite, v4GroupIDs[0], false, 0); err != nil {
		t.Fatalf("EnsurePoliciesForShard (v4): %v", err)
	}
	if err := zm.EnsurePoliciesForShard(context.Background(), testSite, v6GroupIDs[0], true, 0); err != nil {
		t.Fatalf("EnsurePoliciesForShard (v6): %v", err)
	}

	// Find the created dst IP TML (v4).
	tmls, err := ctrl.ListTrafficMatchingLists(context.Background(), testSite)
	if err != nil {
		t.Fatalf("ListTrafficMatchingLists: %v", err)
	}
	var dstIPTML *controller.TrafficMatchingList
	for i := range tmls {
		if strings.HasPrefix(tmls[i].Name, "crowdsec-dstips-v4-") {
			dstIPTML = &tmls[i]
			break
		}
	}
	if dstIPTML == nil {
		t.Fatal("expected crowdsec-dstips-v4-* TML to be created during Bootstrap")
	}

	// Both the v4 and v6 shard policies must carry the v4 dst IP TML ID.
	policies, err := ctrl.ListZonePolicies(context.Background(), testSite)
	if err != nil {
		t.Fatalf("ListZonePolicies: %v", err)
	}
	var v4Policy, v6Policy *controller.ZonePolicy
	for i := range policies {
		switch policies[i].IPVersion {
		case "IPV4":
			v4Policy = &policies[i]
		case "IPV6":
			v6Policy = &policies[i]
		}
	}
	if v4Policy == nil {
		t.Fatal("expected v4 block policy to be created")
	}
	if v6Policy == nil {
		t.Fatal("expected v6 block policy to be created")
	}
	if v4Policy.DstIPTMLID != dstIPTML.ID {
		t.Errorf("v4 policy DstIPTMLID = %q, want %q", v4Policy.DstIPTMLID, dstIPTML.ID)
	}
	if v6Policy.DstIPTMLID != dstIPTML.ID {
		t.Errorf("v6 policy DstIPTMLID = %q, want %q (v4-only dst IPs must reuse v4 TML for v6 policy)", v6Policy.DstIPTMLID, dstIPTML.ID)
	}
}

// TestZoneManager_EnsurePolicies_AllowPolicy_Preserved verifies that an ALLOW
// policy (e.g. a Cloudflare whitelist policy) bearing our description is never
// deleted by the block-policy orphan sweep, even if it carries our description.
// The bouncer's block manager only creates BLOCK actions; ALLOW is out of scope.
func TestZoneManager_EnsurePolicies_AllowPolicy_Preserved(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := testutil.NewMockStore()
	namer := zoneTestNamer(t)

	v4 := ensuredZoneV4Shard(t, ctrl, store)
	zm := newTestZoneManager(ctrl, store, namer)

	if err := zm.Bootstrap(context.Background(), []string{testSite}); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	// An ALLOW policy with our block description — must never be touched.
	// (In practice this shouldn't exist, but if it does, we must not delete it.)
	allowPolicy := controller.ZonePolicy{
		ID:          "allow-policy-id",
		Name:        "crowdsec-policy-wan-dmz-v4-0",
		Description: "test", // matches zm.cfg.Description
		Action:      "ALLOW",
		Enabled:     true,
	}
	ctrl.SetPolicies(testSite, []controller.ZonePolicy{allowPolicy})

	if err := zm.EnsurePolicies(context.Background(), testSite, v4, nil); err != nil {
		t.Fatalf("EnsurePolicies: %v", err)
	}

	if got := ctrl.Calls("DeleteZonePolicy"); got != 0 {
		t.Errorf("DeleteZonePolicy calls: got %d, want 0 (ALLOW policy must never be deleted by block sweep)", got)
	}
}

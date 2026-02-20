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
	sm := NewShardManager(testSite, false, 5, namer, ctrl, store, zerolog.Nop())
	if err := sm.EnsureShards(context.Background()); err != nil {
		t.Fatalf("EnsureShards (v4): %v", err)
	}
	return sm
}

// ensuredZoneV6Shard creates and ensures a v6 ShardManager for zone tests.
func ensuredZoneV6Shard(t *testing.T, ctrl controller.Controller, store storage.Store) *ShardManager {
	t.Helper()
	namer := zoneTestNamer(t)
	sm := NewShardManager(testSite, true, 5, namer, ctrl, store, zerolog.Nop())
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

// TestZoneManager_PolicyReorder verifies that when PolicyReorder=true,
// EnsurePolicies calls ReorderZonePolicies.
func TestZoneManager_PolicyReorder(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := testutil.NewMockStore()
	namer := zoneTestNamer(t)

	v4 := ensuredZoneV4Shard(t, ctrl, store)

	zm := NewZoneManager(ZoneConfig{
		ZonePairs:     []config.ZonePair{{Src: "wan", Dst: "lan"}},
		PolicyReorder: true,
		Description:   "test",
	}, namer, ctrl, store, zerolog.Nop())

	if err := zm.EnsurePolicies(context.Background(), testSite, v4, nil); err != nil {
		t.Fatalf("EnsurePolicies: %v", err)
	}

	if got := ctrl.Calls("ReorderZonePolicies"); got < 1 {
		t.Errorf("ReorderZonePolicies calls: got %d, want >= 1", got)
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

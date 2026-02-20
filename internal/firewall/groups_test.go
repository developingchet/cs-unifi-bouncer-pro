package firewall

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/rs/zerolog"
)

const testSite = "default"

// testNamer returns a Namer using the default templates.
func testNamer(t *testing.T) *Namer {
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

// newBboltStore creates a temporary bbolt store for the test.
func newBboltStore(t *testing.T) storage.Store {
	t.Helper()
	store, err := storage.NewBboltStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewBboltStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// newV4ShardManager creates a new v4 ShardManager with a small capacity.
func newV4ShardManager(t *testing.T, capacity int, ctrl controller.Controller, store storage.Store) *ShardManager {
	t.Helper()
	return NewShardManager(testSite, false, capacity, testNamer(t), ctrl, store, zerolog.Nop())
}

// TestEnsureShards_FirstRun verifies that an empty store causes the first shard
// to be created via the API (CreateFirewallGroup called once).
func TestEnsureShards_FirstRun(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := newBboltStore(t)

	sm := newV4ShardManager(t, 5, ctrl, store)
	if err := sm.EnsureShards(context.Background()); err != nil {
		t.Fatalf("EnsureShards: %v", err)
	}

	if got := ctrl.Calls("CreateFirewallGroup"); got != 1 {
		t.Errorf("CreateFirewallGroup calls: got %d, want 1", got)
	}
	if len(sm.GroupIDs()) != 1 {
		t.Errorf("GroupIDs len: got %d, want 1", len(sm.GroupIDs()))
	}
}

// TestEnsureShards_FromCache verifies that when bbolt and API both know about
// an existing group, no CreateFirewallGroup call is made, and the existing
// member is reflected by Contains.
func TestEnsureShards_FromCache(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := newBboltStore(t)

	const existingIP = "1.2.3.4"
	const existingID = "pre-existing-id"

	// Seed the bbolt cache to simulate a previously-known shard.
	groupName := "crowdsec-block-v4-0"
	if err := store.SetGroup(groupName, storage.GroupRecord{
		UnifiID: existingID,
		Site:    testSite,
		Members: []string{existingIP},
		IPv6:    false,
	}); err != nil {
		t.Fatalf("SetGroup: %v", err)
	}

	// Seed the API with the same group so EnsureShards finds it in apiByID.
	ctrl.SetGroups(testSite, []controller.FirewallGroup{
		{ID: existingID, Name: groupName, GroupType: "address-group", GroupMembers: []string{existingIP}},
	})

	sm := newV4ShardManager(t, 5, ctrl, store)
	if err := sm.EnsureShards(context.Background()); err != nil {
		t.Fatalf("EnsureShards: %v", err)
	}

	// No new shard should have been created.
	if got := ctrl.Calls("CreateFirewallGroup"); got != 0 {
		t.Errorf("CreateFirewallGroup calls: got %d, want 0", got)
	}
	if !sm.Contains(existingIP) {
		t.Errorf("Contains(%q) = false; want true", existingIP)
	}
}

// TestEnsureShards_PrefersAPIOverCache verifies that when the bbolt cache has
// one member ("old-ip") but the live API reports a different member ("new-ip"),
// the API data wins.
func TestEnsureShards_PrefersAPIOverCache(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := newBboltStore(t)

	const existingID = "group-id-1"
	const groupName = "crowdsec-block-v4-0"

	// Seed bbolt with the stale member.
	if err := store.SetGroup(groupName, storage.GroupRecord{
		UnifiID: existingID,
		Site:    testSite,
		Members: []string{"old-ip"},
		IPv6:    false,
	}); err != nil {
		t.Fatalf("SetGroup: %v", err)
	}

	// API has a fresher view.
	ctrl.SetGroups(testSite, []controller.FirewallGroup{
		{ID: existingID, Name: groupName, GroupType: "address-group", GroupMembers: []string{"new-ip"}},
	})

	sm := newV4ShardManager(t, 5, ctrl, store)
	if err := sm.EnsureShards(context.Background()); err != nil {
		t.Fatalf("EnsureShards: %v", err)
	}

	if !sm.Contains("new-ip") {
		t.Error("Contains(\"new-ip\") = false; want true")
	}
	if sm.Contains("old-ip") {
		t.Error("Contains(\"old-ip\") = true; want false")
	}
}

// TestAdd_Basic verifies that adding an IP makes it findable and adds a group ID.
func TestAdd_Basic(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := newBboltStore(t)

	sm := newV4ShardManager(t, 5, ctrl, store)
	if err := sm.EnsureShards(context.Background()); err != nil {
		t.Fatalf("EnsureShards: %v", err)
	}

	_, err := sm.Add(context.Background(), "10.0.0.1")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	if len(sm.GroupIDs()) != 1 {
		t.Errorf("GroupIDs len: got %d, want 1", len(sm.GroupIDs()))
	}
	if !sm.Contains("10.0.0.1") {
		t.Error("Contains(\"10.0.0.1\") = false; want true")
	}
}

// TestAdd_Idempotent verifies that adding the same IP twice results in only
// one copy in AllMembers.
func TestAdd_Idempotent(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := newBboltStore(t)

	sm := newV4ShardManager(t, 5, ctrl, store)
	if err := sm.EnsureShards(context.Background()); err != nil {
		t.Fatalf("EnsureShards: %v", err)
	}

	_, _ = sm.Add(context.Background(), "10.0.0.1")
	_, _ = sm.Add(context.Background(), "10.0.0.1")

	members := sm.AllMembers()
	count := 0
	for _, m := range members {
		if m == "10.0.0.1" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("AllMembers contains %d copies of 10.0.0.1; want 1", count)
	}
}

// TestAdd_NewShardOnOverflow verifies that adding capacity+1 IPs causes a
// second shard to be created. EnsureShards creates the first shard (1 call),
// and the overflow IP triggers a second create (total 2 calls).
func TestAdd_NewShardOnOverflow(t *testing.T) {
	const capacity = 3
	ctrl := testutil.NewMockController()
	store := newBboltStore(t)

	sm := newV4ShardManager(t, capacity, ctrl, store)
	if err := sm.EnsureShards(context.Background()); err != nil {
		t.Fatalf("EnsureShards: %v", err)
	}

	// Fill first shard to capacity, then add one more.
	for i := 0; i <= capacity; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i+1)
		if _, err := sm.Add(context.Background(), ip); err != nil {
			t.Fatalf("Add(%s): %v", ip, err)
		}
	}

	if got := ctrl.Calls("CreateFirewallGroup"); got != 2 {
		t.Errorf("CreateFirewallGroup calls: got %d, want 2", got)
	}
	if len(sm.GroupIDs()) != 2 {
		t.Errorf("GroupIDs len: got %d, want 2", len(sm.GroupIDs()))
	}
}

// TestRemove_Basic verifies that adding and then removing an IP causes Contains
// to return false.
func TestRemove_Basic(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := newBboltStore(t)

	sm := newV4ShardManager(t, 5, ctrl, store)
	if err := sm.EnsureShards(context.Background()); err != nil {
		t.Fatalf("EnsureShards: %v", err)
	}

	if _, err := sm.Add(context.Background(), "10.0.0.1"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := sm.Remove(context.Background(), "10.0.0.1"); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	if sm.Contains("10.0.0.1") {
		t.Error("Contains(\"10.0.0.1\") = true after Remove; want false")
	}
}

// TestRemove_Idempotent verifies that removing an IP not present does not error
// and does not panic.
func TestRemove_Idempotent(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := newBboltStore(t)

	sm := newV4ShardManager(t, 5, ctrl, store)
	if err := sm.EnsureShards(context.Background()); err != nil {
		t.Fatalf("EnsureShards: %v", err)
	}

	if _, err := sm.Remove(context.Background(), "192.168.1.1"); err != nil {
		t.Fatalf("Remove of missing IP returned error: %v", err)
	}
}

// TestFlushDirty_UpdatesAPI verifies that after adding an IP, FlushDirty
// calls UpdateFirewallGroup exactly once.
func TestFlushDirty_UpdatesAPI(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := newBboltStore(t)

	sm := newV4ShardManager(t, 5, ctrl, store)
	if err := sm.EnsureShards(context.Background()); err != nil {
		t.Fatalf("EnsureShards: %v", err)
	}

	if _, err := sm.Add(context.Background(), "10.0.0.1"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := sm.FlushDirty(context.Background()); err != nil {
		t.Fatalf("FlushDirty: %v", err)
	}

	if got := ctrl.Calls("UpdateFirewallGroup"); got != 1 {
		t.Errorf("UpdateFirewallGroup calls: got %d, want 1", got)
	}
}

// TestFlushDirty_SkipsClean verifies that FlushDirty does not call
// UpdateFirewallGroup when no changes have been made.
func TestFlushDirty_SkipsClean(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := newBboltStore(t)

	sm := newV4ShardManager(t, 5, ctrl, store)
	if err := sm.EnsureShards(context.Background()); err != nil {
		t.Fatalf("EnsureShards: %v", err)
	}

	if err := sm.FlushDirty(context.Background()); err != nil {
		t.Fatalf("FlushDirty: %v", err)
	}

	if got := ctrl.Calls("UpdateFirewallGroup"); got != 0 {
		t.Errorf("UpdateFirewallGroup calls: got %d, want 0", got)
	}
}

// TestFlushDirty_APIError verifies that when UpdateFirewallGroup returns an
// error, FlushDirty propagates it.
func TestFlushDirty_APIError(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := newBboltStore(t)

	sm := newV4ShardManager(t, 5, ctrl, store)
	if err := sm.EnsureShards(context.Background()); err != nil {
		t.Fatalf("EnsureShards: %v", err)
	}

	if _, err := sm.Add(context.Background(), "10.0.0.1"); err != nil {
		t.Fatalf("Add: %v", err)
	}

	ctrl.SetError("UpdateFirewallGroup", fmt.Errorf("api unavailable"))
	err := sm.FlushDirty(context.Background())
	if err == nil {
		t.Error("FlushDirty: expected error from UpdateFirewallGroup, got nil")
	}
}

// TestAllMembers_AcrossShards verifies that when two shards exist, AllMembers
// returns IPs from both shards.
func TestAllMembers_AcrossShards(t *testing.T) {
	const capacity = 2
	ctrl := testutil.NewMockController()
	store := newBboltStore(t)

	sm := newV4ShardManager(t, capacity, ctrl, store)
	if err := sm.EnsureShards(context.Background()); err != nil {
		t.Fatalf("EnsureShards: %v", err)
	}

	ips := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	for _, ip := range ips {
		if _, err := sm.Add(context.Background(), ip); err != nil {
			t.Fatalf("Add(%s): %v", ip, err)
		}
	}

	members := sm.AllMembers()
	if len(members) != len(ips) {
		t.Errorf("AllMembers len: got %d, want %d", len(members), len(ips))
	}

	memberSet := make(map[string]struct{}, len(members))
	for _, m := range members {
		memberSet[m] = struct{}{}
	}
	for _, ip := range ips {
		if _, ok := memberSet[ip]; !ok {
			t.Errorf("AllMembers missing %q", ip)
		}
	}
}

// TestGroupIDs verifies that GroupIDs returns the UniFi IDs of all shards.
func TestGroupIDs(t *testing.T) {
	const capacity = 2
	ctrl := testutil.NewMockController()
	store := newBboltStore(t)

	sm := newV4ShardManager(t, capacity, ctrl, store)
	if err := sm.EnsureShards(context.Background()); err != nil {
		t.Fatalf("EnsureShards: %v", err)
	}

	// Force a second shard by overflowing the first.
	for i := 0; i <= capacity; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i+1)
		if _, err := sm.Add(context.Background(), ip); err != nil {
			t.Fatalf("Add(%s): %v", ip, err)
		}
	}

	ids := sm.GroupIDs()
	if len(ids) != 2 {
		t.Errorf("GroupIDs len: got %d, want 2", len(ids))
	}
	for i, id := range ids {
		if id == "" {
			t.Errorf("GroupIDs[%d] is empty string", i)
		}
	}
}

// TestConcurrentAddRemove verifies that concurrent Add and Remove calls do not
// cause data races. Run with -race to exercise the mutex paths.
func TestConcurrentAddRemove(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping concurrent test in short mode")
	}

	const goroutines = 20
	ctrl := testutil.NewMockController()
	store := newBboltStore(t)

	sm := newV4ShardManager(t, 100, ctrl, store)
	if err := sm.EnsureShards(context.Background()); err != nil {
		t.Fatalf("EnsureShards: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	for i := 0; i < goroutines; i++ {
		ip := fmt.Sprintf("10.1.%d.%d", i/256, i%256)
		go func(ip string) {
			defer wg.Done()
			_, _ = sm.Add(context.Background(), ip)
		}(ip)
		go func(ip string) {
			defer wg.Done()
			_, _ = sm.Remove(context.Background(), ip)
		}(ip)
	}

	wg.Wait()
}

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

func newShardTestStore(t *testing.T) storage.Store {
	t.Helper()
	store, err := storage.NewBboltStore(t.TempDir(), zerolog.Nop())
	if err != nil {
		t.Fatalf("NewBboltStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func newShardTestNamer(t *testing.T) *Namer {
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

func newShardTestManager(t *testing.T, mode string, capacity int) (*ShardManager, *testutil.MockController) {
	t.Helper()
	ctrl := testutil.NewMockController()
	store := newShardTestStore(t)
	sm := NewShardManager(testSite, false, capacity, newShardTestNamer(t), ctrl, store, zerolog.Nop(), 0, nil, false, mode)
	if err := sm.EnsureShards(context.Background()); err != nil {
		t.Fatalf("EnsureShards: %v", err)
	}
	// With lazy creation, add a dummy IP to create shard 0 for testing
	if _, _, err := sm.Add(context.Background(), "10.0.0.0"); err != nil {
		t.Fatalf("Add dummy IP: %v", err)
	}
	// Remove it so the shard exists but is empty for capacity testing
	if _, err := sm.Remove(context.Background(), "10.0.0.0"); err != nil {
		t.Fatalf("Remove dummy IP: %v", err)
	}
	return sm, ctrl
}

func familyState(t *testing.T, sm *ShardManager) *ShardFamily {
	t.Helper()
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	family := sm.families[sm.family]
	if family == nil {
		t.Fatal("expected family state")
	}
	return family
}

func shardIPCounts(family *ShardFamily) []int {
	counts := make([]int, 0, len(family.Shards))
	for _, shard := range family.Shards {
		counts = append(counts, shard.IPs.Len())
	}
	return counts
}

func countIPAcrossShards(family *ShardFamily, ip string) int {
	count := 0
	for _, shard := range family.Shards {
		if shard.IPs.Contains(ip) {
			count++
		}
	}
	return count
}

func TestAddIP_Deduplication(t *testing.T) {
	sm, _ := newShardTestManager(t, "legacy", 3)

	if err := sm.AddIP(context.Background(), "1.2.3.4", "v4"); err != nil {
		t.Fatalf("AddIP first: %v", err)
	}
	if err := sm.AddIP(context.Background(), "1.2.3.4", "v4"); err != nil {
		t.Fatalf("AddIP second: %v", err)
	}

	family := familyState(t, sm)
	if got := len(family.ipOwner); got != 1 {
		t.Fatalf("ipOwner len = %d, want 1", got)
	}
	if got := family.Shards[0].IPs.Len(); got != 1 {
		t.Fatalf("shard0 len = %d, want 1", got)
	}
	if got := countIPAcrossShards(family, "1.2.3.4"); got != 1 {
		t.Fatalf("IP appears %d times across shards, want 1", got)
	}
}

func TestAddIP_BinPack(t *testing.T) {
	sm, _ := newShardTestManager(t, "legacy", 3)

	for i := 1; i <= 5; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i)
		if err := sm.AddIP(context.Background(), ip, "v4"); err != nil {
			t.Fatalf("AddIP(%s): %v", ip, err)
		}
	}

	family := familyState(t, sm)
	if got := len(family.Shards); got != 2 {
		t.Fatalf("shards = %d, want 2", got)
	}
	counts := shardIPCounts(family)
	if counts[0] != 3 || counts[1] != 2 {
		t.Fatalf("counts = %v, want [3 2]", counts)
	}
	for i := 1; i <= 5; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i)
		if got := countIPAcrossShards(family, ip); got != 1 {
			t.Fatalf("IP %s appears %d times, want 1", ip, got)
		}
	}
}

func TestAddIP_ExactCapacity(t *testing.T) {
	sm, _ := newShardTestManager(t, "legacy", 2)

	for i := 1; i <= 4; i++ {
		ip := fmt.Sprintf("10.0.1.%d", i)
		if err := sm.AddIP(context.Background(), ip, "v4"); err != nil {
			t.Fatalf("AddIP(%s): %v", ip, err)
		}
	}

	family := familyState(t, sm)
	if got := len(family.Shards); got != 2 {
		t.Fatalf("shards = %d, want 2", got)
	}
	counts := shardIPCounts(family)
	if counts[0] != 2 || counts[1] != 2 {
		t.Fatalf("counts = %v, want [2 2]", counts)
	}
}

func TestAddIP_LargeOverflow(t *testing.T) {
	sm, _ := newShardTestManager(t, "legacy", ShardLimit)
	ctx := context.Background()

	// Seed baseline:
	// shard0 = 9999, shard1 = 2000
	sm.mu.Lock()
	family := sm.familyStateLocked("v4")
	shard0 := family.Shards[0]
	sm.mu.Unlock()

	for i := 0; i < 9999; i++ {
		ip := fmt.Sprintf("198.51.0.%d", i)
		if shard0.IPs.Add(ip) {
			sm.mu.Lock()
			family.ipOwner[ip] = shard0.Index
			sm.mu.Unlock()
		}
	}
	shard0.IPs.MarkClean()

	shard1, err := sm.createShard(ctx, 1)
	if err != nil {
		t.Fatalf("createShard(1): %v", err)
	}
	sm.mu.Lock()
	family = sm.familyStateLocked("v4")
	family.Shards = append(family.Shards, shard1)
	sm.mu.Unlock()
	for i := 0; i < 2000; i++ {
		ip := fmt.Sprintf("198.52.0.%d", i)
		if shard1.IPs.Add(ip) {
			sm.mu.Lock()
			family.ipOwner[ip] = shard1.Index
			sm.mu.Unlock()
		}
	}
	shard1.IPs.MarkClean()

	// Add 10002 new IPs:
	// shard0 +1 => 10000
	// shard1 +8000 => 10000
	// shard2 => 2001
	for i := 0; i < 10002; i++ {
		ip := fmt.Sprintf("203.0.%d.%d", i/256, i%256)
		if err := sm.AddIP(ctx, ip, "v4"); err != nil {
			t.Fatalf("AddIP(%s): %v", ip, err)
		}
	}

	family = familyState(t, sm)
	if got := len(family.Shards); got != 3 {
		t.Fatalf("shards = %d, want 3", got)
	}

	counts := shardIPCounts(family)
	if counts[0] != 10000 || counts[1] != 10000 || counts[2] != 2001 {
		t.Fatalf("counts = %v, want [10000 10000 2001]", counts)
	}

	if got := len(family.ipOwner); got != 22001 {
		t.Fatalf("ipOwner len = %d, want 22001", got)
	}

	// Spot-check uniqueness for newly added range.
	for i := 0; i < 10002; i += 997 {
		ip := fmt.Sprintf("203.0.%d.%d", i/256, i%256)
		if got := countIPAcrossShards(family, ip); got != 1 {
			t.Fatalf("IP %s appears %d times, want 1", ip, got)
		}
	}
}

func TestRemoveIP_UpdatesOwner(t *testing.T) {
	sm, _ := newShardTestManager(t, "legacy", 3)

	ip := "10.10.10.10"
	if err := sm.AddIP(context.Background(), ip, "v4"); err != nil {
		t.Fatalf("AddIP: %v", err)
	}
	sm.RemoveIP(ip, "v4")

	family := familyState(t, sm)
	if _, ok := family.ipOwner[ip]; ok {
		t.Fatal("ipOwner still contains removed IP")
	}
	if family.Shards[0].IPs.Contains(ip) {
		t.Fatal("shard still contains removed IP")
	}
}

func TestRemoveIP_Idempotent(t *testing.T) {
	sm, _ := newShardTestManager(t, "legacy", 3)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("RemoveIP panicked: %v", r)
		}
	}()

	sm.RemoveIP("203.0.113.99", "v4")

	family := familyState(t, sm)
	if got := len(family.ipOwner); got != 0 {
		t.Fatalf("ipOwner len = %d, want 0", got)
	}
}

func TestNoDuplicatesAcrossShards(t *testing.T) {
	sm, _ := newShardTestManager(t, "legacy", 1)

	ip := "1.2.3.4"
	if err := sm.AddIP(context.Background(), ip, "v4"); err != nil {
		t.Fatalf("AddIP: %v", err)
	}
	if _, _, err := sm.Add(context.Background(), ip); err != nil {
		t.Fatalf("Add wrapper: %v", err)
	}

	family := familyState(t, sm)
	if got := countIPAcrossShards(family, ip); got != 1 {
		t.Fatalf("IP appears %d times, want 1", got)
	}
	if _, ok := family.ipOwner[ip]; !ok {
		t.Fatal("ipOwner missing expected IP")
	}
}

func TestSyncLoop_OnlyDirtyShards(t *testing.T) {
	sm, ctrl := newShardTestManager(t, "zone", 1)

	if err := sm.AddIP(context.Background(), "10.0.0.1", "v4"); err != nil {
		t.Fatalf("AddIP shard0: %v", err)
	}
	if err := sm.AddIP(context.Background(), "10.0.0.2", "v4"); err != nil {
		t.Fatalf("AddIP shard1: %v", err)
	}

	family := familyState(t, sm)
	if got := len(family.Shards); got != 2 {
		t.Fatalf("shards = %d, want 2", got)
	}

	// Keep shard0 dirty, mark shard1 clean.
	family.Shards[1].IPs.MarkClean()
	ctrl.SetError("UpdateTrafficMatchingList", nil)

	_ = sm.syncAllFamilies(context.Background())

	if got := ctrl.Calls("UpdateTrafficMatchingList"); got != 1 {
		t.Fatalf("UpdateTrafficMatchingList calls = %d, want 1", got)
	}
}

func TestSyncLoop_RetryOnError(t *testing.T) {
	sm, ctrl := newShardTestManager(t, "zone", 3)

	if err := sm.AddIP(context.Background(), "10.20.30.40", "v4"); err != nil {
		t.Fatalf("AddIP: %v", err)
	}

	family := familyState(t, sm)
	ctrl.SetError("UpdateTrafficMatchingList", fmt.Errorf("boom"))

	_ = sm.syncShard(context.Background(), family.Shards[0])

	if !family.Shards[0].IPs.IsDirty() {
		t.Fatal("expected shard to remain dirty after failed sync")
	}
}

func TestEnsureShards_LoadsExisting(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := newShardTestStore(t)
	namer := newShardTestNamer(t)

	const shardName = "crowdsec-block-v4-0"
	const shardID = "tml-0"
	if err := store.SetGroup(shardName, storage.GroupRecord{
		UnifiID: shardID,
		Site:    testSite,
		IPv6:    false,
	}); err != nil {
		t.Fatalf("SetGroup: %v", err)
	}

	ctrl.SetTMLs(testSite, []controller.TrafficMatchingList{
		{
			ID:   shardID,
			Name: shardName,
			Type: "IPV4_ADDRESSES",
			Items: []controller.TrafficMatchingListItem{
				{Value: "1.1.1.1"},
				{Value: "2.2.2.2"},
				{Value: "3.3.3.3"},
			},
		},
	})

	sm := NewShardManager(testSite, false, 10000, namer, ctrl, store, zerolog.Nop(), 0, nil, false, "zone")
	if err := sm.EnsureShards(context.Background()); err != nil {
		t.Fatalf("EnsureShards: %v", err)
	}

	family := familyState(t, sm)
	if got := len(family.Shards); got != 1 {
		t.Fatalf("shards = %d, want 1", got)
	}
	if got := family.Shards[0].ID; got != shardID {
		t.Fatalf("shard ID = %s, want %s", got, shardID)
	}
	if got := family.Shards[0].Name; got != shardName {
		t.Fatalf("shard name = %s, want %s", got, shardName)
	}
	if got := family.Shards[0].IPs.Len(); got != 3 {
		t.Fatalf("shard len = %d, want 3", got)
	}
	if family.Shards[0].IPs.IsDirty() {
		t.Fatal("expected baseline shard to be clean")
	}
}

// TestAddIP_ConcurrentShardBoundary exercises the TOCTOU race that previously
// caused "no available shard capacity" errors in production.  Multiple goroutines
// all call AddIP simultaneously when every existing shard is at or near capacity
// (shardLimit=3).  They all observe a full shard, and previously they would all
// compute the same nextIndex, race to re-acquire the lock, and all but the winner
// would find the freshly-created shard already full — returning an error instead
// of allocating a new shard.  The fix holds the lock for the full alloc+append
// sequence, eliminating the window entirely.
func TestAddIP_ConcurrentShardBoundary(t *testing.T) {
	// capacity=3 means each shard holds exactly 3 IPs, forcing many shard
	// creations with a modest goroutine count.
	sm, _ := newShardTestManager(t, "legacy", 3)
	ctx := context.Background()

	const goroutines = 60
	errs := make([]error, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			ip := fmt.Sprintf("10.2.0.%d", i)
			errs[i] = sm.AddIP(ctx, ip, "v4")
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d AddIP error: %v", i, err)
		}
	}

	family := familyState(t, sm)
	// All goroutines added unique IPs so ipOwner must contain all of them.
	if got := len(family.ipOwner); got != goroutines {
		t.Errorf("ipOwner len = %d, want %d", got, goroutines)
	}
	// Every IP must appear in exactly one shard (no duplicates, no missing).
	for i := 0; i < goroutines; i++ {
		ip := fmt.Sprintf("10.2.0.%d", i)
		if got := countIPAcrossShards(family, ip); got != 1 {
			t.Errorf("IP %s appears %d times across shards, want 1", ip, got)
		}
	}
}

func TestSyncAllFamilies_ConcurrentWithAddIP(t *testing.T) {
	sm, _ := newShardTestManager(t, "zone", 3)
	ctx := context.Background()

	// Use enough IPs to force shard overflow (capacity=3 in test config).
	// Each overflow calls AddIP again with nextIndex, which allocates and appends
	// a new shard to family.Shards under sm.mu. This ensures the Shards slice is
	// actually mutated during the race window, not just accessed.
	const iterations = 200
	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine 1: repeatedly add IPs (mutates Shards slice when overflow occurs)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			ip := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
			_ = sm.AddIP(ctx, ip, "v4")
		}
	}()

	// Goroutine 2: repeatedly call syncAllFamilies (walks Shards slice)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_ = sm.syncAllFamilies(ctx)
		}
	}()

	wg.Wait()
}

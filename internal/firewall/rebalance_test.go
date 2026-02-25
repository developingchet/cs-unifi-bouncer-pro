package firewall

import (
	"context"
	"fmt"
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
)

// setupShards populates a ShardManager's family with a set of pre-built shards and
// returns the shard slice for assertions. Must be called before any method that
// acquires sm.mu (Rebalance, etc.).
func setupShards(t *testing.T, sm *ShardManager, shards []*Shard) {
	t.Helper()
	sm.mu.Lock()
	defer sm.mu.Unlock()
	family := sm.familyStateLocked(sm.family)
	family.Shards = shards
	// Rebuild ipOwner from the provided shards.
	clear(family.ipOwner)
	for _, s := range shards {
		for _, ip := range s.IPs.Members() {
			family.ipOwner[ip] = s.Index
		}
	}
}

// makeActiveShard creates an Active shard with the given index and IP count.
func makeActiveShard(t *testing.T, sm *ShardManager, idx, ipCount int) *Shard {
	t.Helper()
	name, err := sm.namer.GroupName(NameData{Family: sm.family, Index: idx, Site: sm.site})
	if err != nil {
		t.Fatalf("GroupName(idx=%d): %v", idx, err)
	}
	s := &Shard{
		ID:     fmt.Sprintf("id-%d", idx),
		Name:   name,
		Index:  idx,
		Family: sm.family,
		IPs:    NewIPSet(),
		State:  ShardStateActive,
	}
	for i := 0; i < ipCount; i++ {
		s.IPs.Add(fmt.Sprintf("10.%d.%d.%d", idx, i/256, i%256))
	}
	s.IPs.MarkClean()
	return s
}

// makePendingShard creates a Pending shard with the given index and IP count.
func makePendingShard(t *testing.T, sm *ShardManager, idx, ipCount int) *Shard {
	t.Helper()
	name, err := sm.namer.GroupName(NameData{Family: sm.family, Index: idx, Site: sm.site})
	if err != nil {
		t.Fatalf("GroupName(idx=%d): %v", idx, err)
	}
	s := &Shard{
		ID:     "",
		Name:   name,
		Index:  idx,
		Family: sm.family,
		IPs:    NewIPSet(),
		State:  ShardStatePending,
	}
	for i := 0; i < ipCount; i++ {
		s.IPs.Add(fmt.Sprintf("10.%d.%d.%d", idx, i/256, i%256))
	}
	s.IPs.MarkClean()
	return s
}

// TestRebalance_TwoHalfFullMerge verifies that two half-full shards are merged:
// shard0 (7 IPs, anchor) receives donor shard1 (3 IPs), shard1 transitions to Draining.
func TestRebalance_TwoHalfFullMerge(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := newBboltStore(t)
	sm := newV4ShardManager(t, 10, ctrl, store)

	shard0 := makeActiveShard(t, sm, 0, 7)
	shard1 := makeActiveShard(t, sm, 1, 3)
	setupShards(t, sm, []*Shard{shard0, shard1})

	n := sm.Rebalance(context.Background())

	if n != 1 {
		t.Errorf("Rebalance() = %d; want 1", n)
	}
	if shard1.State != ShardStateDraining {
		t.Errorf("shard1.State = %v; want ShardStateDraining", shard1.State)
	}
	if got := shard0.IPs.Len(); got != 10 {
		t.Errorf("shard0.IPs.Len() = %d; want 10", got)
	}
	if got := shard1.IPs.Len(); got != 0 {
		t.Errorf("shard1.IPs.Len() = %d; want 0 (donor was cleared)", got)
	}

	// Verify ipOwner map was updated: all IPs now belong to shard0.
	sm.mu.RLock()
	family := sm.families[sm.family]
	for ip, owner := range family.ipOwner {
		if owner != 0 {
			t.Errorf("ipOwner[%q] = %d; want 0 (all IPs should belong to shard0)", ip, owner)
		}
	}
	sm.mu.RUnlock()
}

// TestRebalance_NoRoomForDonor verifies that a donor below threshold cannot merge when
// the only target would overflow the shard limit (3 + 9 = 12 > 10).
func TestRebalance_NoRoomForDonor(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := newBboltStore(t)
	sm := newV4ShardManager(t, 10, ctrl, store)

	shard0 := makeActiveShard(t, sm, 0, 9) // anchor, 9 IPs
	shard1 := makeActiveShard(t, sm, 1, 3) // donor candidate, but 3+9=12 > 10
	setupShards(t, sm, []*Shard{shard0, shard1})

	n := sm.Rebalance(context.Background())

	if n != 0 {
		t.Errorf("Rebalance() = %d; want 0 (no merge possible)", n)
	}
	if shard1.State != ShardStateActive {
		t.Errorf("shard1.State = %v; want ShardStateActive (no change)", shard1.State)
	}
	if got := shard0.IPs.Len(); got != 9 {
		t.Errorf("shard0.IPs.Len() = %d; want 9 (unchanged)", got)
	}
}

// TestRebalance_AnchorShardNeverDonates verifies that index-0 shard is never a donor
// even when below threshold, and that shard1 (non-anchor) donates into shard0.
func TestRebalance_AnchorShardNeverDonates(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := newBboltStore(t)
	sm := newV4ShardManager(t, 10, ctrl, store)

	// threshold = shardLimit/2 = 5
	shard0 := makeActiveShard(t, sm, 0, 1) // anchor: 1 IP, below threshold but index=0
	shard1 := makeActiveShard(t, sm, 1, 5) // donor: 5 IPs <= threshold(5); target = shard0
	setupShards(t, sm, []*Shard{shard0, shard1})

	n := sm.Rebalance(context.Background())

	if n != 1 {
		t.Errorf("Rebalance() = %d; want 1 (shard1 merges into shard0)", n)
	}
	if shard1.State != ShardStateDraining {
		t.Errorf("shard1.State = %v; want ShardStateDraining", shard1.State)
	}
	if shard0.State != ShardStateActive {
		t.Errorf("shard0.State = %v; want ShardStateActive (anchor unchanged)", shard0.State)
	}
	if got := shard0.IPs.Len(); got != 6 {
		t.Errorf("shard0.IPs.Len() = %d; want 6 (1 original + 5 merged)", got)
	}
}

// TestRebalance_PendingShardSkipped verifies that Pending shards are never donors or targets.
func TestRebalance_PendingShardSkipped(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := newBboltStore(t)
	sm := newV4ShardManager(t, 10, ctrl, store)

	shard0 := makeActiveShard(t, sm, 0, 8)  // anchor, no donations
	shard1 := makePendingShard(t, sm, 1, 0) // Pending: neither donor nor target
	setupShards(t, sm, []*Shard{shard0, shard1})

	n := sm.Rebalance(context.Background())

	if n != 0 {
		t.Errorf("Rebalance() = %d; want 0 (Pending shard skipped)", n)
	}
	if shard1.State != ShardStatePending {
		t.Errorf("shard1.State = %v; want ShardStatePending (unchanged)", shard1.State)
	}
}

// TestRebalance_NegativeThresholdDisables verifies that setting threshold to -1
// disables all rebalancing even when shards are clearly merge-eligible.
func TestRebalance_NegativeThresholdDisables(t *testing.T) {
	ctrl := testutil.NewMockController()
	store := newBboltStore(t)
	sm := newV4ShardManager(t, 10, ctrl, store)
	sm.SetMergeThreshold(-1) // disable

	shard0 := makeActiveShard(t, sm, 0, 7)
	shard1 := makeActiveShard(t, sm, 1, 3)
	setupShards(t, sm, []*Shard{shard0, shard1})

	n := sm.Rebalance(context.Background())

	if n != 0 {
		t.Errorf("Rebalance() = %d; want 0 (rebalancing disabled)", n)
	}
	if shard1.State != ShardStateActive {
		t.Errorf("shard1.State = %v; want ShardStateActive (no change when disabled)", shard1.State)
	}
	if got := shard0.IPs.Len(); got != 7 {
		t.Errorf("shard0.IPs.Len() = %d; want 7 (unchanged)", got)
	}
}

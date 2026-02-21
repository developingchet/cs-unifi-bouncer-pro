package firewall

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/rs/zerolog"
)

// ShardManager manages a set of firewall group shards for one address family on one site.
type ShardManager struct {
	mu         sync.RWMutex
	site       string
	ipv6       bool
	capacity   int
	namer      *Namer
	ctrl       controller.Controller
	store      storage.Store
	log        zerolog.Logger
	flushDelay time.Duration
	flushSem   chan struct{} // shared semaphore; nil = unlimited
	dryRun     bool

	// In-memory shadow of each shard's members
	shards []shard // index == shard number
}

type shard struct {
	unifiID string
	members map[string]struct{}
	dirty   bool
}

// flushSnapshot captures the data needed to flush a dirty shard without holding the lock.
type flushSnapshot struct {
	idx     int
	unifiID string
	name    string
	members []string // sorted
}

// NewShardManager creates a ShardManager. Call EnsureShards to initialize from the API.
func NewShardManager(site string, ipv6 bool, capacity int, namer *Namer,
	ctrl controller.Controller, store storage.Store, log zerolog.Logger,
	flushDelay time.Duration, flushSem chan struct{}, dryRun bool) *ShardManager {
	return &ShardManager{
		site:       site,
		ipv6:       ipv6,
		capacity:   capacity,
		namer:      namer,
		ctrl:       ctrl,
		store:      store,
		log:        log,
		flushDelay: flushDelay,
		flushSem:   flushSem,
		dryRun:     dryRun,
	}
}

// EnsureShards bootstraps group shards: loads from bbolt cache, then reconciles with API.
func (sm *ShardManager) EnsureShards(ctx context.Context) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Load all known group records from bbolt
	allGroups, err := sm.store.ListGroups()
	if err != nil {
		return fmt.Errorf("list groups from store: %w", err)
	}

	// Fetch current state from UniFi
	apiGroups, err := sm.ctrl.ListFirewallGroups(ctx, sm.site)
	if err != nil {
		return fmt.Errorf("list firewall groups from API: %w", err)
	}
	apiByID := make(map[string]controller.FirewallGroup, len(apiGroups))
	for _, g := range apiGroups {
		apiByID[g.ID] = g
	}

	// Rebuild shard slice from bbolt records
	idx := 0
	for {
		name, err := sm.namer.GroupName(NameData{
			Family: Family(sm.ipv6),
			Index:  idx,
			Site:   sm.site,
		})
		if err != nil {
			return err
		}

		rec, ok := allGroups[name]
		if !ok {
			break // no more shards recorded
		}
		if rec.IPv6 != sm.ipv6 || rec.Site != sm.site {
			idx++
			continue
		}

		members := make(map[string]struct{}, len(rec.Members))
		// Prefer live API data over stale bbolt cache
		if apiGroup, exists := apiByID[rec.UnifiID]; exists {
			for _, m := range apiGroup.GroupMembers {
				members[m] = struct{}{}
			}
		} else {
			for _, m := range rec.Members {
				members[m] = struct{}{}
			}
		}

		sm.shards = append(sm.shards, shard{
			unifiID: rec.UnifiID,
			members: members,
		})
		idx++
	}

	// If no shards yet, create the first one
	if len(sm.shards) == 0 {
		if err := sm.createShard(ctx, 0); err != nil {
			return err
		}
	}

	sm.updateMetrics()
	return nil
}

// Add adds an IP to the appropriate shard, creating new shards as needed.
// Returns the shard name that was modified (for batch flushing) and the index of a
// newly created shard (newShardIdx >= 0), or newShardIdx == -1 if no new shard was created.
func (sm *ShardManager) Add(ctx context.Context, ip string) (shardName string, newShardIdx int, err error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	newShardIdx = -1

	// Check if already present
	for _, s := range sm.shards {
		if _, ok := s.members[ip]; ok {
			return "", -1, nil // already there
		}
	}

	// Find a shard with capacity
	shardIdx := -1
	for i, s := range sm.shards {
		if len(s.members) < sm.capacity {
			shardIdx = i
			break
		}
	}

	// All shards full — create a new one
	if shardIdx < 0 {
		shardIdx = len(sm.shards)
		if err := sm.createShard(ctx, shardIdx); err != nil {
			return "", -1, err
		}
		newShardIdx = shardIdx
	}

	sm.shards[shardIdx].members[ip] = struct{}{}
	sm.shards[shardIdx].dirty = true

	name, err := sm.namer.GroupName(NameData{Family: Family(sm.ipv6), Index: shardIdx, Site: sm.site})
	if err != nil {
		return "", newShardIdx, err
	}
	sm.updateMetrics()
	return name, newShardIdx, nil
}

// Remove removes an IP from whichever shard contains it.
func (sm *ShardManager) Remove(ctx context.Context, ip string) (string, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	for i, s := range sm.shards {
		if _, ok := s.members[ip]; ok {
			delete(sm.shards[i].members, ip)
			sm.shards[i].dirty = true
			name, err := sm.namer.GroupName(NameData{Family: Family(sm.ipv6), Index: i, Site: sm.site})
			if err != nil {
				return "", err
			}
			sm.updateMetrics()
			return name, nil
		}
	}
	return "", nil // not found — idempotent
}

// FlushDirty pushes all dirty shards to the UniFi API.
// The mutex is released before any HTTP call or sleep, allowing Add/Remove to proceed
// concurrently. On failure the affected shard is re-marked dirty for retry.
func (sm *ShardManager) FlushDirty(ctx context.Context) error {
	groupType := "address-group"
	if sm.ipv6 {
		groupType = "ipv6-address-group"
	}

	// --- Phase 1: snapshot dirty shards under lock, clear dirty flags ---
	sm.mu.Lock()
	var snapshots []flushSnapshot
	for i := range sm.shards {
		if !sm.shards[i].dirty {
			continue
		}

		members := make([]string, 0, len(sm.shards[i].members))
		for m := range sm.shards[i].members {
			members = append(members, m)
		}
		sort.Strings(members)

		name, err := sm.namer.GroupName(NameData{Family: Family(sm.ipv6), Index: i, Site: sm.site})
		if err != nil {
			sm.mu.Unlock()
			return err
		}

		snapshots = append(snapshots, flushSnapshot{
			idx:     i,
			unifiID: sm.shards[i].unifiID,
			name:    name,
			members: members,
		})
		sm.shards[i].dirty = false
	}
	sm.mu.Unlock()

	if sm.dryRun {
		for _, snap := range snapshots {
			sm.log.Info().
				Str("shard", snap.name).
				Int("member_count", len(snap.members)).
				Msg("[DRY-RUN] would flush firewall group")
		}
		return nil
	}

	// --- Phase 2: flush each snapshot without holding the lock ---
	var firstErr error
	for i, snap := range snapshots {
		// Apply inter-shard delay (not before the first one)
		if i > 0 && sm.flushDelay > 0 {
			select {
			case <-time.After(sm.flushDelay):
			case <-ctx.Done():
				// Re-mark remaining snapshots as dirty
				sm.mu.Lock()
				for _, s := range snapshots[i:] {
					sm.shards[s.idx].dirty = true
				}
				sm.mu.Unlock()
				return ctx.Err()
			}
		}

		// Acquire semaphore slot
		if sm.flushSem != nil {
			select {
			case sm.flushSem <- struct{}{}:
			case <-ctx.Done():
				sm.mu.Lock()
				for _, s := range snapshots[i:] {
					sm.shards[s.idx].dirty = true
				}
				sm.mu.Unlock()
				return ctx.Err()
			}
		}

		putErr := sm.ctrl.UpdateFirewallGroup(ctx, sm.site, controller.FirewallGroup{
			ID:           snap.unifiID,
			Name:         snap.name,
			GroupType:    groupType,
			GroupMembers: snap.members,
		})

		// Release semaphore slot
		if sm.flushSem != nil {
			<-sm.flushSem
		}

		if putErr != nil {
			// Re-mark as dirty for retry on next flush
			sm.mu.Lock()
			sm.shards[snap.idx].dirty = true
			sm.mu.Unlock()

			if firstErr == nil {
				firstErr = fmt.Errorf("flush shard %d (%s): %w", snap.idx, snap.name, putErr)
			}
			continue // attempt remaining shards
		}

		// Update bbolt cache
		if err := sm.store.SetGroup(snap.name, storage.GroupRecord{
			UnifiID: snap.unifiID,
			Site:    sm.site,
			Members: snap.members,
			IPv6:    sm.ipv6,
		}); err != nil {
			sm.log.Warn().Err(err).Str("shard", snap.name).Msg("failed to update bbolt group cache")
		}
	}

	return firstErr
}

// PrunableTail returns the last shard's UniFi ID and index if it is pruneable:
// empty (0 members) AND not the only shard (len > 1).
// Returns ok=false if pruning is not applicable.
func (sm *ShardManager) PrunableTail() (unifiID string, shardIdx int, ok bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if len(sm.shards) <= 1 {
		return "", -1, false
	}

	last := sm.shards[len(sm.shards)-1]
	if len(last.members) > 0 {
		return "", -1, false
	}

	return last.unifiID, len(sm.shards) - 1, true
}

// RemoveTail removes the last shard from in-memory slice and bbolt.
// Call only after the API group has been successfully deleted.
func (sm *ShardManager) RemoveTail() error {
	sm.mu.Lock()
	n := len(sm.shards)
	if n == 0 {
		sm.mu.Unlock()
		return nil
	}
	name, nameErr := sm.namer.GroupName(NameData{Family: Family(sm.ipv6), Index: n - 1, Site: sm.site})
	sm.shards = sm.shards[:n-1]
	sm.mu.Unlock()

	if nameErr != nil {
		return nameErr
	}
	return sm.store.DeleteGroup(name)
}

// Contains returns true if any shard contains the given IP.
func (sm *ShardManager) Contains(ip string) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	for _, s := range sm.shards {
		if _, ok := s.members[ip]; ok {
			return true
		}
	}
	return false
}

// AllMembers returns all IPs across all shards.
func (sm *ShardManager) AllMembers() []string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	var all []string
	for _, s := range sm.shards {
		for m := range s.members {
			all = append(all, m)
		}
	}
	return all
}

// createShard creates a new empty group shard in UniFi and registers it in bbolt.
func (sm *ShardManager) createShard(ctx context.Context, idx int) error {
	name, err := sm.namer.GroupName(NameData{Family: Family(sm.ipv6), Index: idx, Site: sm.site})
	if err != nil {
		return err
	}

	if sm.dryRun {
		sm.log.Info().Str("name", name).Bool("ipv6", sm.ipv6).Int("shard", idx).
			Msg("[DRY-RUN] would create firewall group shard")
		sm.shards = append(sm.shards, shard{
			unifiID: "dry-run-no-id",
			members: make(map[string]struct{}),
		})
		return nil
	}

	groupType := "address-group"
	if sm.ipv6 {
		groupType = "ipv6-address-group"
	}

	created, err := sm.ctrl.CreateFirewallGroup(ctx, sm.site, controller.FirewallGroup{
		Name:         name,
		GroupType:    groupType,
		GroupMembers: []string{},
	})
	if err != nil {
		return fmt.Errorf("create shard %s: %w", name, err)
	}

	sm.shards = append(sm.shards, shard{
		unifiID: created.ID,
		members: make(map[string]struct{}),
	})

	if err := sm.store.SetGroup(name, storage.GroupRecord{
		UnifiID: created.ID,
		Site:    sm.site,
		Members: []string{},
		IPv6:    sm.ipv6,
	}); err != nil {
		sm.log.Warn().Err(err).Str("shard", name).Msg("failed to cache new shard in bbolt")
	}

	sm.log.Info().Str("name", name).Str("id", created.ID).Msg("created firewall group shard")
	return nil
}

// GroupIDs returns all UniFi IDs of the managed shards.
func (sm *ShardManager) GroupIDs() []string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	ids := make([]string, 0, len(sm.shards))
	for _, s := range sm.shards {
		ids = append(ids, s.unifiID)
	}
	return ids
}

func (sm *ShardManager) updateMetrics() {
	family := Family(sm.ipv6)
	for i, s := range sm.shards {
		name, _ := sm.namer.GroupName(NameData{Family: family, Index: i, Site: sm.site})
		metrics.FirewallGroupSize.WithLabelValues(family, name, sm.site).Set(float64(len(s.members)))
	}
}

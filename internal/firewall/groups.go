package firewall

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/rs/zerolog"
)

// ShardManager manages a set of firewall group shards for one address family on one site.
type ShardManager struct {
	mu       sync.RWMutex
	site     string
	ipv6     bool
	capacity int
	namer    *Namer
	ctrl     controller.Controller
	store    storage.Store
	log      zerolog.Logger

	// In-memory shadow of each shard's members
	shards []shard // index == shard number
}

type shard struct {
	unifiID string
	members map[string]struct{}
	dirty   bool
}

// NewShardManager creates a ShardManager. Call EnsureShards to initialize from the API.
func NewShardManager(site string, ipv6 bool, capacity int, namer *Namer,
	ctrl controller.Controller, store storage.Store, log zerolog.Logger) *ShardManager {
	return &ShardManager{
		site:     site,
		ipv6:     ipv6,
		capacity: capacity,
		namer:    namer,
		ctrl:     ctrl,
		store:    store,
		log:      log,
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
// Returns the shard name that was modified (for batch flushing).
func (sm *ShardManager) Add(ctx context.Context, ip string) (string, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Check if already present
	for _, s := range sm.shards {
		if _, ok := s.members[ip]; ok {
			return "", nil // already there
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
			return "", err
		}
	}

	sm.shards[shardIdx].members[ip] = struct{}{}
	sm.shards[shardIdx].dirty = true

	name, err := sm.namer.GroupName(NameData{Family: Family(sm.ipv6), Index: shardIdx, Site: sm.site})
	if err != nil {
		return "", err
	}
	sm.updateMetrics()
	return name, nil
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
func (sm *ShardManager) FlushDirty(ctx context.Context) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	for i := range sm.shards {
		if !sm.shards[i].dirty {
			continue
		}

		members := make([]string, 0, len(sm.shards[i].members))
		for m := range sm.shards[i].members {
			members = append(members, m)
		}
		sort.Strings(members)

		groupType := "address-group"
		if sm.ipv6 {
			groupType = "ipv6-address-group"
		}

		name, err := sm.namer.GroupName(NameData{Family: Family(sm.ipv6), Index: i, Site: sm.site})
		if err != nil {
			return err
		}

		if err := sm.ctrl.UpdateFirewallGroup(ctx, sm.site, controller.FirewallGroup{
			ID:           sm.shards[i].unifiID,
			Name:         name,
			GroupType:    groupType,
			GroupMembers: members,
		}); err != nil {
			return fmt.Errorf("flush shard %d (%s): %w", i, name, err)
		}

		// Update bbolt cache
		if err := sm.store.SetGroup(name, storage.GroupRecord{
			UnifiID: sm.shards[i].unifiID,
			Site:    sm.site,
			Members: members,
			IPv6:    sm.ipv6,
		}); err != nil {
			sm.log.Warn().Err(err).Str("shard", name).Msg("failed to update bbolt group cache")
		}

		sm.shards[i].dirty = false
	}
	return nil
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

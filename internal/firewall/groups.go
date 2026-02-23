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

// ShardLimit is the maximum number of IPs per Traffic Matching List shard.
// UniFi integration v1 supports up to 10,000 items per TML.
const ShardLimit = 10_000

// Shard represents a single Traffic Matching List shard in zone mode.
// In legacy mode, it represents a firewall group shard.
type Shard struct {
	ID     string // TML UUID (integration v1) or firewall group ID (legacy)
	Name   string // "crowdsec-block-v4-0" or similar
	Index  int    // shard number (0, 1, 2, ...)
	Family string // "v4" or "v6"
	IPs    *IPSet // in-memory authoritative IP set
}

// ShardManager manages a set of firewall group shards for one address family on one site.
// In zone mode, shards are Traffic Matching Lists; in legacy mode, they are firewall groups.
type ShardManager struct {
	mu         sync.RWMutex
	site       string
	ipv6       bool
	capacity   int // deprecated: use ShardLimit constant instead
	namer      *Namer
	ctrl       controller.Controller
	store      storage.Store
	log        zerolog.Logger
	flushDelay time.Duration
	flushSem   chan struct{} // shared semaphore; nil = unlimited
	dryRun     bool
	mode       string // "legacy" or "zone" (used for log messaging only)

	// In-memory shadow of each shard's members
	shards []Shard // index == shard number
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
	flushDelay time.Duration, flushSem chan struct{}, dryRun bool, mode string) *ShardManager {
	if mode == "" {
		mode = "legacy"
	}
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
		mode:       mode,
	}
}

func (sm *ShardManager) shardObjectKind() string {
	if sm.mode == "zone" {
		return "traffic matching list"
	}
	return "firewall group"
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

	// Fetch current state from UniFi (dispatched by mode).
	// In zone mode, use TML API; in legacy mode, use firewall groups.
	var apiGroupByID map[string]controller.FirewallGroup
	var apiTMLByName map[string]controller.TrafficMatchingList
	if sm.mode == "zone" {
		tmls, err := sm.ctrl.ListTrafficMatchingLists(ctx, sm.site)
		if err != nil {
			return fmt.Errorf("list traffic matching lists from API: %w", err)
		}
		apiTMLByName = make(map[string]controller.TrafficMatchingList, len(tmls))
		for _, t := range tmls {
			apiTMLByName[t.Name] = t
		}
	} else {
		apiGroups, err := sm.ctrl.ListFirewallGroups(ctx, sm.site)
		if err != nil {
			return fmt.Errorf("list firewall groups from API: %w", err)
		}
		apiGroupByID = make(map[string]controller.FirewallGroup, len(apiGroups))
		for _, g := range apiGroups {
			apiGroupByID[g.ID] = g
		}
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

		foundInAPI := false

		// Prefer live API data over stale bbolt cache.
		// In zone mode, match by name (TMLs have stable UUIDs stored in bbolt already).
		// In legacy mode, match by ID.
		if sm.mode == "zone" {
			if tml, exists := apiTMLByName[name]; exists {
				// Load existing members as baseline
				members := make([]string, 0, len(tml.Items))
				for _, item := range tml.Items {
					members = append(members, item.Value)
				}
				shard := &Shard{
					ID:     tml.ID,
					Name:   tml.Name,
					Index:  idx,
					Family: Family(sm.ipv6),
					IPs:    NewIPSet(),
				}
				shard.IPs.Replace(members)
				shard.IPs.MarkClean() // baseline is not dirty

				// Update bbolt record with current TML ID in case it changed.
				rec.UnifiID = tml.ID
				foundInAPI = true
				sm.shards = append(sm.shards, *shard)
				idx++
				continue
			}
		} else {
			if apiGroup, exists := apiGroupByID[rec.UnifiID]; exists {
				// Load existing members as baseline
				members := make([]string, len(apiGroup.GroupMembers))
				copy(members, apiGroup.GroupMembers)
				shard := &Shard{
					ID:     rec.UnifiID,
					Name:   name,
					Index:  idx,
					Family: Family(sm.ipv6),
					IPs:    NewIPSet(),
				}
				shard.IPs.Replace(members)
				shard.IPs.MarkClean() // baseline is not dirty
				sm.shards = append(sm.shards, *shard)
				foundInAPI = true
				idx++
				continue
			}
		}

		if !foundInAPI {
			// Cached object no longer exists in API for this mode. Recreate and
			// mark dirty so members are pushed on the next flush.
			if err := sm.createShard(ctx, idx); err != nil {
				return err
			}
			// The new shard already has an empty IPSet
			if len(rec.Members) > 0 {
				// Mark dirty to push the old members
				sm.shards[idx].IPs.Replace(rec.Members)
				sm.shards[idx].IPs.MarkClean() // will be set dirty by replace above, but let's be explicit
			}
			idx++
		}
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
		if s.IPs.Contains(ip) {
			return "", -1, nil // already there
		}
	}

	// Find a shard with capacity
	shardIdx := -1
	for i, s := range sm.shards {
		if s.IPs.Capacity(sm.capacity) > 0 {
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

	sm.shards[shardIdx].IPs.Add(ip)

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
		if s.IPs.Remove(ip) {
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
	tmlType := "IPV4_ADDRESSES"
	if sm.ipv6 {
		tmlType = "IPV6_ADDRESSES"
	}
	objectKind := sm.shardObjectKind()

	// --- Phase 1: snapshot dirty shards under lock, clear dirty flags ---
	sm.mu.Lock()
	var snapshots []flushSnapshot
	for i := range sm.shards {
		ips, dirty := sm.shards[i].IPs.PeekDirty()
		if !dirty {
			continue
		}

		members := make([]string, 0, len(ips))
		for _, m := range ips {
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
			unifiID: sm.shards[i].ID,
			name:    name,
			members: members,
		})
		// Clear dirty flag now so Add/Remove can proceed
		sm.shards[i].IPs.MarkClean()
	}
	sm.mu.Unlock()

	if sm.dryRun {
		for _, snap := range snapshots {
			sm.log.Info().
				Str("shard", snap.name).
				Int("member_count", len(snap.members)).
				Msgf("[DRY-RUN] would flush %s", objectKind)
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
					// Restore dirty flag
					sm.shards[s.idx].IPs.Replace(snap.members)
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
					// Restore dirty flag
					sm.shards[s.idx].IPs.Replace(snap.members)
				}
				sm.mu.Unlock()
				return ctx.Err()
			}
		}

		var putErr error
		if sm.mode == "zone" {
			items := make([]controller.TrafficMatchingListItem, 0, len(snap.members))
			for _, m := range snap.members {
				items = append(items, controller.TrafficMatchingListItem{Value: m})
			}
			putErr = sm.ctrl.UpdateTrafficMatchingList(ctx, sm.site, controller.TrafficMatchingList{
				ID:        snap.unifiID,
				Name:      snap.name,
				Type:      tmlType,
				GroupType: groupType,
				Items:     items,
			})
		} else {
			putErr = sm.ctrl.UpdateFirewallGroup(ctx, sm.site, controller.FirewallGroup{
				ID:           snap.unifiID,
				Name:         snap.name,
				GroupType:    groupType,
				GroupMembers: snap.members,
			})
		}

		// Release semaphore slot
		if sm.flushSem != nil {
			<-sm.flushSem
		}

		if putErr != nil {
			// Re-mark as dirty for retry on next flush
			sm.mu.Lock()
			sm.shards[snap.idx].IPs.Replace(snap.members)
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
	if last.IPs.Len() > 0 {
		return "", -1, false
	}

	return last.ID, len(sm.shards) - 1, true
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

// DeleteShardObject deletes the backing UniFi object for a shard ID.
// In zone mode this deletes a Traffic Matching List; in legacy mode a FirewallGroup.
func (sm *ShardManager) DeleteShardObject(ctx context.Context, unifiID string) error {
	if sm.mode == "zone" {
		return sm.ctrl.DeleteTrafficMatchingList(ctx, sm.site, unifiID)
	}
	return sm.ctrl.DeleteFirewallGroup(ctx, sm.site, unifiID)
}

// Contains returns true if any shard contains the given IP.
func (sm *ShardManager) Contains(ip string) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	for _, s := range sm.shards {
		if s.IPs.Contains(ip) {
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
		all = append(all, s.IPs.Members()...)
	}
	return all
}

// createShard creates a new empty shard in UniFi and registers it in bbolt.
// In zone mode this creates a Traffic Matching List; in legacy mode a FirewallGroup.
func (sm *ShardManager) createShard(ctx context.Context, idx int) error {
	name, err := sm.namer.GroupName(NameData{Family: Family(sm.ipv6), Index: idx, Site: sm.site})
	if err != nil {
		return err
	}

	objectKind := sm.shardObjectKind()

	if sm.dryRun {
		sm.log.Info().Str("name", name).Bool("ipv6", sm.ipv6).Int("shard", idx).
			Msgf("[DRY-RUN] would create %s", objectKind)
		sm.shards = append(sm.shards, Shard{
			ID:      "dry-run-no-id",
			Name:    name,
			Index:   idx,
			Family:  Family(sm.ipv6),
			IPs:     NewIPSet(),
		})
		return nil
	}

	var createdID string

	if sm.mode == "zone" {
		tmlType := "IPV4_ADDRESSES"
		groupType := "address-group"
		if sm.ipv6 {
			tmlType = "IPV6_ADDRESSES"
			groupType = "ipv6-address-group"
		}
		created, err := sm.ctrl.CreateTrafficMatchingList(ctx, sm.site, controller.TrafficMatchingList{
			Name:      name,
			Type:      tmlType,
			GroupType: groupType,
			Items:     []controller.TrafficMatchingListItem{},
		})
		if err != nil {
			return fmt.Errorf("create shard %s: %w", name, err)
		}
		createdID = created.ID
	} else {
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
		createdID = created.ID
	}

	sm.shards = append(sm.shards, Shard{
		ID:      createdID,
		Name:    name,
		Index:   idx,
		Family:  Family(sm.ipv6),
		IPs:     NewIPSet(),
	})

	if err := sm.store.SetGroup(name, storage.GroupRecord{
		UnifiID: createdID,
		Site:    sm.site,
		Members: []string{},
		IPv6:    sm.ipv6,
	}); err != nil {
		sm.log.Warn().Err(err).Str("shard", name).Msg("failed to cache new shard in bbolt")
	}

	sm.log.Info().Str("name", name).Str("id", createdID).Msgf("created %s", objectKind)
	return nil
}

// GroupIDs returns all UniFi IDs of the managed shards.
func (sm *ShardManager) GroupIDs() []string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	ids := make([]string, 0, len(sm.shards))
	for _, s := range sm.shards {
		ids = append(ids, s.ID)
	}
	return ids
}

func (sm *ShardManager) updateMetrics() {
	family := Family(sm.ipv6)
	for i, s := range sm.shards {
		name, _ := sm.namer.GroupName(NameData{Family: family, Index: i, Site: sm.site})
		metrics.FirewallGroupSize.WithLabelValues(family, name, sm.site).Set(float64(s.IPs.Len()))
	}
}

package firewall

import (
	"context"
	"errors"
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

// TMLPlaceholderV4 and TMLPlaceholderV6 are RFC 5737 / RFC 3849 documentation
// addresses used as placeholder items when creating an empty TML shard.
// The UniFi API rejects empty items arrays on both create and update (HTTP 400).
// These addresses are in reserved documentation ranges and will never match real traffic.
const (
	TMLPlaceholderV4 = "192.0.2.1"      // RFC 5737 TEST-NET-1 (plain IP, not CIDR)
	TMLPlaceholderV6 = "2001:db8::1"    // RFC 3849 (plain IP, not CIDR)
)

// tmlPlaceholderItems returns a slice with the appropriate placeholder IP
// for the given IPv6 flag. This ensures the TML always has at least one item.
func tmlPlaceholderItems(ipv6 bool) []controller.TrafficMatchingListItem {
	val := TMLPlaceholderV4
	if ipv6 {
		val = TMLPlaceholderV6
	}
	return []controller.TrafficMatchingListItem{{Type: "IP_ADDRESS", Value: val}}
}

// ShardState represents the lifecycle state of a shard.
type ShardState uint8

// Shard state constants.
const (
	ShardStatePending  ShardState = iota // allocated in-memory, not yet in UniFi (no IPs assigned)
	ShardStateActive                      // exists in UniFi, has ≥1 real IP
	ShardStateDraining                    // IPs all removed, deletion sequence in progress
)

// Shard represents a single Traffic Matching List shard in zone mode.
// In legacy mode, it represents a firewall group shard.
type Shard struct {
	ID     string     // TML UUID (integration v1) or firewall group ID (legacy), empty if Pending
	Name   string     // "crowdsec-block-v4-0" or similar
	Index  int        // shard number (0, 1, 2, ...)
	Family string     // "v4" or "v6"
	IPs    *IPSet     // in-memory authoritative IP set
	State  ShardState // current lifecycle state

	// onDrainedFired is set to true after onDrained has been called once for
	// this shard. Prevents duplicate policy/rule deletion attempts on retry ticks.
	onDrainedFired bool
}

// orphanedGroup represents a placeholder-only UniFi group found during EnsureShards
// that should be deleted (policies/rules first, then the group itself).
type orphanedGroup struct {
	UnifiID string // group ID in UniFi
	Name    string // group name (for logging)
}

// ShardFamily tracks shard state and unique IP ownership for one IP family.
type ShardFamily struct {
	Shards []*Shard
	// ipOwner maps each banned IP to the shard index that owns it.
	// Guarded by ShardManager.mu.
	ipOwner map[string]int
}

// ShardManager manages a set of firewall group shards for one address family on one site.
// In zone mode, shards are Traffic Matching Lists; in legacy mode, they are firewall groups.
type ShardManager struct {
	mu         sync.RWMutex
	site       string
	ipv6       bool
	family     string
	shardLimit int
	namer      *Namer
	ctrl       controller.Controller
	store      storage.Store
	log        zerolog.Logger
	flushDelay time.Duration
	flushSem   chan struct{} // shared semaphore; nil = unlimited
	dryRun     bool
	mode       string // "legacy" or "zone" (used for log messaging only)

	// Per-family shard state. In this codebase each ShardManager owns one
	// family ("v4" for ipv6=false, "v6" for ipv6=true), but the map keeps
	// AddIP/RemoveIP explicit and future-proof.
	families map[string]*ShardFamily

	// onActivated is called when a Pending shard becomes Active (transitions to UniFi after first flush).
	// Called with (ctx, shardIdx, groupID).
	onActivated func(ctx context.Context, shardIdx int, groupID string)

	// onRateLimit is called when a shard sync returns ErrRateLimit.
	// The manager uses this to back off future flushes.
	onRateLimit func(retryAfter time.Duration)

	// onSyncError is called when a shard PUT fails (non-rate-limit errors).
	// The manager uses this to trip the circuit breaker.
	onSyncError func()

	// onSyncSuccess is called after a successful shard PUT.
	// The manager uses this to reset the circuit breaker.
	onSyncSuccess func()

	// onDrained is called when a Draining shard is about to have its UniFi object
	// deleted. The callback should delete the shard's policies/rules first so UniFi
	// does not reject the group deletion due to remaining references.
	// Called with (ctx, shardIdx, groupID).
	onDrained func(ctx context.Context, shardIdx int, groupID string)

	// mergeThreshold is the IP count at or below which a shard is eligible for
	// consolidation into a larger shard. 0 = auto (shardLimit/2). -1 = disabled.
	mergeThreshold int

	// orphanedGroups is populated by EnsureShards with placeholder-only groups found in UniFi.
	// These groups should be deleted (policies/rules first, then the group).
	// Guarded by mu.
	orphanedGroups []orphanedGroup
}

// flushSnapshot captures the data needed to flush a dirty shard without holding the lock.
type flushSnapshot struct {
	shard   *Shard  // reference to the shard (for state transitions and callbacks)
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

	family := Family(ipv6)
	limit := capacity
	if limit <= 0 {
		limit = ShardLimit
	}

	return &ShardManager{
		site:       site,
		ipv6:       ipv6,
		family:     family,
		shardLimit: limit,
		namer:      namer,
		ctrl:       ctrl,
		store:      store,
		log:        log,
		flushDelay: flushDelay,
		flushSem:   flushSem,
		dryRun:     dryRun,
		mode:       mode,
		families: map[string]*ShardFamily{
			family: {
				Shards:  []*Shard{},
				ipOwner: make(map[string]int),
			},
		},
	}
}

// SetActivationCallback sets the function to be called when a shard transitions from Pending to Active.
// Called during syncShard() with (ctx, shardIdx, groupID).
func (sm *ShardManager) SetActivationCallback(fn func(ctx context.Context, shardIdx int, groupID string)) {
	sm.onActivated = fn
}

// SetRateLimitCallback sets the function to be called when a shard sync returns ErrRateLimit.
func (sm *ShardManager) SetRateLimitCallback(fn func(retryAfter time.Duration)) {
	sm.onRateLimit = fn
}

// SetSyncCallbacks sets callbacks for shard sync success and non-rate-limit errors.
// Used by the manager to drive the circuit breaker.
func (sm *ShardManager) SetSyncCallbacks(onSuccess func(), onError func()) {
	sm.onSyncSuccess = onSuccess
	sm.onSyncError = onError
}

// SetDrainCallback sets the function called when a Draining shard is about to have
// its UniFi object deleted. The callback must remove the shard's policies/rules first.
func (sm *ShardManager) SetDrainCallback(fn func(ctx context.Context, shardIdx int, groupID string)) {
	sm.onDrained = fn
}

// SetMergeThreshold configures the IP count at or below which a shard is eligible
// for consolidation. 0 = auto (shardLimit/2). -1 = disable rebalancing.
func (sm *ShardManager) SetMergeThreshold(n int) {
	sm.mergeThreshold = n
}

// TakeOrphanedGroups returns and clears the list of placeholder-only groups found during EnsureShards.
// These are groups that exist in UniFi but contain only placeholder IPs and should be deleted.
func (sm *ShardManager) TakeOrphanedGroups() []orphanedGroup {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	result := sm.orphanedGroups
	sm.orphanedGroups = nil
	return result
}

func (sm *ShardManager) shardObjectKind() string {
	if sm.mode == "zone" {
		return "traffic matching list"
	}
	return "firewall group"
}

func (sm *ShardManager) familyStateLocked(ipFamily string) *ShardFamily {
	family := sm.families[ipFamily]
	if family == nil {
		family = &ShardFamily{
			Shards:  []*Shard{},
			ipOwner: make(map[string]int),
		}
		sm.families[ipFamily] = family
	}
	if family.ipOwner == nil {
		family.ipOwner = make(map[string]int)
	}
	return family
}

func (sm *ShardManager) findShardByIndexLocked(family *ShardFamily, shardIdx int) (*Shard, int) {
	for pos, shard := range family.Shards {
		if shard.Index == shardIdx {
			return shard, pos
		}
	}
	return nil, -1
}

// EnsureShards bootstraps group shards: loads from bbolt cache, then reconciles with API.
func (sm *ShardManager) EnsureShards(ctx context.Context) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	family := sm.familyStateLocked(sm.family)
	family.Shards = family.Shards[:0]
	clear(family.ipOwner)

	// Load all known group records from bbolt.
	allGroups, err := sm.store.ListGroups()
	if err != nil {
		return fmt.Errorf("list groups from store: %w", err)
	}

	// Fetch current state from UniFi (dispatched by mode).
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

	// Rebuild shards from bbolt records by naming sequence.
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
			break
		}
		if rec.IPv6 != sm.ipv6 || rec.Site != sm.site {
			idx++
			continue
		}

		var shard *Shard
		foundInAPI := false

		if sm.mode == "zone" {
			if tml, exists := apiTMLByName[name]; exists {
				members := make([]string, 0, len(tml.Items))
				for _, item := range tml.Items {
					if item.Value == TMLPlaceholderV4 || item.Value == TMLPlaceholderV6 {
						continue // strip creation placeholder
					}
					members = append(members, item.Value)
				}

				// Detect placeholder-only groups (orphans)
				if len(members) == 0 {
					sm.orphanedGroups = append(sm.orphanedGroups, orphanedGroup{UnifiID: tml.ID, Name: tml.Name})
				} else {
					shard = &Shard{ID: tml.ID, Name: tml.Name, Index: idx, Family: Family(sm.ipv6), IPs: NewIPSet(), State: ShardStateActive}
					shard.IPs.Replace(members)
					shard.IPs.MarkClean()

					if rec.UnifiID != tml.ID {
						if err := sm.store.SetGroup(name, storage.GroupRecord{
							UnifiID: tml.ID,
							Site:    sm.site,
							Members: members,
							IPv6:    sm.ipv6,
						}); err != nil {
							sm.log.Warn().Err(err).Str("shard", name).Msg("failed to refresh shard cache entry")
						}
					}
				}
				foundInAPI = true
			}
		} else {
			if apiGroup, exists := apiGroupByID[rec.UnifiID]; exists {
				// Legacy mode: strip placeholder from GroupMembers like zone mode does
				members := make([]string, 0, len(apiGroup.GroupMembers))
				for _, m := range apiGroup.GroupMembers {
					if m == TMLPlaceholderV4 || m == TMLPlaceholderV6 {
						continue // strip creation placeholder
					}
					members = append(members, m)
				}

				// Detect placeholder-only groups (orphans)
				if len(members) == 0 {
					sm.orphanedGroups = append(sm.orphanedGroups, orphanedGroup{UnifiID: apiGroup.ID, Name: apiGroup.Name})
				} else {
					shard = &Shard{ID: rec.UnifiID, Name: name, Index: idx, Family: Family(sm.ipv6), IPs: NewIPSet(), State: ShardStateActive}
					shard.IPs.Replace(members)
					shard.IPs.MarkClean()
				}
				foundInAPI = true
			}
		}

		if !foundInAPI {
			// Allocate a Pending shard in-memory without creating in UniFi yet.
			shard = sm.allocShard(idx)
			if len(rec.Members) > 0 {
				// Keep dirty so old members are restored on next sync tick.
				shard.IPs.Replace(rec.Members)
			}
		}

		// Only add to family.Shards if shard was created (not an orphan)
		if shard != nil {
			family.Shards = append(family.Shards, shard)
		}
		idx++
	}

	// Lazy shard creation: do not create an initial shard if none are loaded from bbolt.
	// Shards are created only when the first IP is assigned to them (via AddIP).
	// This prevents empty shards from existing in UniFi unnecessarily.

	sort.Slice(family.Shards, func(i, j int) bool {
		return family.Shards[i].Index < family.Shards[j].Index
	})

	// Duplicate resolution rule:
	// When loading baseline state and duplicates exist across shards, the
	// lowest-index shard is the keeper. Duplicates are removed from higher-index
	// shards and those shards are left dirty for sync.
	for _, shard := range family.Shards {
		for _, ip := range shard.IPs.Members() {
			if _, exists := family.ipOwner[ip]; exists {
				shard.IPs.Remove(ip)
				sm.log.Warn().Str("shard", shard.Name).Str("ip", ip).
					Msg("removed duplicate IP from higher-index shard during baseline load")
				continue
			}
			family.ipOwner[ip] = shard.Index
		}
	}

	sm.updateMetricsLocked()
	return nil
}

// AddIP adds ip to the appropriate shard for ipFamily ("v4" or "v6").
// If ip is already tracked in any shard, it is a no-op (deduplication).
// If all shards are full or draining, a new Pending shard is allocated
// in-memory and the IP is placed into it immediately. The shard will be
// created in UniFi on the next flush.
//
// The lock is held for the entire operation. allocShard is pure in-memory
// (template rendering + struct creation, no I/O) so there is no reason to
// drop the lock between the capacity check and the append, which previously
// created a TOCTOU race: concurrent goroutines could all compute the same
// nextIndex, one would win the re-lock and create the shard, and the rest
// would find that shard already full and return an error.
func (sm *ShardManager) AddIP(_ context.Context, ip, ipFamily string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	family := sm.familyStateLocked(ipFamily)

	if _, owned := family.ipOwner[ip]; owned {
		return nil
	}

	for _, shard := range family.Shards {
		if shard.State == ShardStateDraining {
			continue // draining shards cannot accept new IPs
		}
		if shard.IPs.Capacity(sm.shardLimit) > 0 {
			shard.IPs.Add(ip)
			family.ipOwner[ip] = shard.Index
			sm.updateMetricsLocked()
			return nil
		}
	}

	// All existing shards are full or draining — allocate a new Pending shard.
	nextIndex := len(family.Shards)
	shard := sm.allocShard(nextIndex)
	family.Shards = append(family.Shards, shard)
	shard.IPs.Add(ip)
	family.ipOwner[ip] = shard.Index
	sm.updateMetricsLocked()
	return nil
}

// RemoveIP removes ip from whichever shard owns it. No-op if not tracked.
func (sm *ShardManager) RemoveIP(ip, ipFamily string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	family := sm.familyStateLocked(ipFamily)
	shardIdx, owned := family.ipOwner[ip]
	if !owned {
		return
	}

	if shard, _ := sm.findShardByIndexLocked(family, shardIdx); shard != nil {
		shard.IPs.Remove(ip)
	}
	delete(family.ipOwner, ip)
	sm.updateMetricsLocked()
}

// Add adds an IP to the manager family and returns shard details for callers
// that need to provision rule/policy infrastructure when a new shard appears.
func (sm *ShardManager) Add(ctx context.Context, ip string) (shardName string, newShardIdx int, err error) {
	sm.mu.RLock()
	family := sm.families[sm.family]
	before := len(family.Shards)
	sm.mu.RUnlock()

	if err := sm.AddIP(ctx, ip, sm.family); err != nil {
		return "", -1, err
	}

	sm.mu.RLock()
	family = sm.families[sm.family]
	ownerIdx, owned := family.ipOwner[ip]
	after := len(family.Shards)
	sm.mu.RUnlock()
	if !owned {
		return "", -1, nil
	}

	name, err := sm.namer.GroupName(NameData{Family: Family(sm.ipv6), Index: ownerIdx, Site: sm.site})
	if err != nil {
		return "", -1, err
	}

	newShardIdx = -1
	if after > before && ownerIdx >= before {
		newShardIdx = ownerIdx
	}
	return name, newShardIdx, nil
}

// Remove removes an IP from whichever shard contains it.
func (sm *ShardManager) Remove(ctx context.Context, ip string) (string, error) {
	sm.mu.RLock()
	family := sm.families[sm.family]
	shardIdx, owned := family.ipOwner[ip]
	sm.mu.RUnlock()
	if !owned {
		return "", nil
	}

	sm.RemoveIP(ip, sm.family)

	name, err := sm.namer.GroupName(NameData{Family: Family(sm.ipv6), Index: shardIdx, Site: sm.site})
	if err != nil {
		return "", err
	}
	return name, nil
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
	family := sm.familyStateLocked(sm.family)
	var snapshots []flushSnapshot
	for i := range family.Shards {
		shard := family.Shards[i]
		ips, dirty := shard.IPs.PeekDirty()
		if !dirty {
			continue
		}

		// Skip Draining shards; they are handled by pruneEmptyTailShards.
		if shard.State == ShardStateDraining {
			continue
		}

		// Handle Pending→Active transition: POST to create the group first
		if shard.State == ShardStatePending {
			// If Pending and has no IPs, don't create it in UniFi yet.
			if len(ips) == 0 {
				// Clear dirty flag but don't add to snapshots (skip the PUT)
				shard.IPs.MarkClean()
				continue
			}
			// POST to create the group with placeholder
			sm.mu.Unlock()
			createdID, err := sm.doCreateUniFiGroup(ctx, shard.Name)
			if err != nil {
				sm.log.Error().Err(err).Str("shard", shard.Name).Msg("failed to create shard in UniFi during flush")
				sm.mu.Lock()
				// Re-mark as dirty so it will be retried
				shard.IPs.Replace(ips)
				sm.mu.Unlock()
				return err
			}
			shard.ID = createdID
			sm.log.Debug().Str("shard", shard.Name).Str("id", createdID).Msg("created shard in UniFi during flush")
			// Re-acquire lock for the rest of the phase
			if err := sm.store.SetGroup(shard.Name, storage.GroupRecord{
				UnifiID: createdID,
				Site:    sm.site,
				Members: []string{},
				IPv6:    sm.ipv6,
			}); err != nil {
				sm.log.Warn().Err(err).Str("shard", shard.Name).Msg("failed to cache new shard in bbolt after POST")
			}
			sm.mu.Lock()
		}

		members := append(make([]string, 0, len(ips)), ips...)
		sort.Strings(members)

		// UniFi API rejects empty items arrays on both create and update (HTTP 400).
		// Substitute the RFC 5737/3849 placeholder when no real bans exist.
		if len(members) == 0 {
			if sm.ipv6 {
				members = []string{TMLPlaceholderV6}
			} else {
				members = []string{TMLPlaceholderV4}
			}
		}

		name, err := sm.namer.GroupName(NameData{Family: Family(sm.ipv6), Index: shard.Index, Site: sm.site})
		if err != nil {
			sm.mu.Unlock()
			return err
		}

		snapshots = append(snapshots, flushSnapshot{
			shard:   shard,
			idx:     i,
			unifiID: shard.ID,
			name:    name,
			members: members,
		})
		// Clear dirty flag now so Add/Remove can proceed.
		shard.IPs.MarkClean()
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
		if i > 0 && sm.flushDelay > 0 {
			select {
			case <-time.After(sm.flushDelay):
			case <-ctx.Done():
				sm.mu.Lock()
				family := sm.familyStateLocked(sm.family)
				for _, s := range snapshots[i:] {
					family.Shards[s.idx].IPs.Replace(s.members)
				}
				sm.mu.Unlock()
				return ctx.Err()
			}
		}

		if sm.flushSem != nil {
			select {
			case sm.flushSem <- struct{}{}:
			case <-ctx.Done():
				sm.mu.Lock()
				family := sm.familyStateLocked(sm.family)
				for _, s := range snapshots[i:] {
					family.Shards[s.idx].IPs.Replace(s.members)
				}
				sm.mu.Unlock()
				return ctx.Err()
			}
		}

		var putErr error
		if sm.mode == "zone" {
			items := make([]controller.TrafficMatchingListItem, 0, len(snap.members))
			for _, m := range snap.members {
				items = append(items, controller.TrafficMatchingListItem{Type: "IP_ADDRESS", Value: m})
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

		if sm.flushSem != nil {
			<-sm.flushSem
		}

		if putErr != nil {
			sm.mu.Lock()
			family := sm.familyStateLocked(sm.family)
			family.Shards[snap.idx].IPs.Replace(snap.members)
			sm.mu.Unlock()

			if firstErr == nil {
				firstErr = fmt.Errorf("flush shard %d (%s): %w", snap.idx, snap.name, putErr)
			}
			continue
		}

		// Pending→Active transition: mark as Active and fire activation callback
		wasCreating := snap.shard.State == ShardStatePending
		if wasCreating {
			snap.shard.State = ShardStateActive
		}

		if err := sm.store.SetGroup(snap.name, storage.GroupRecord{
			UnifiID: snap.unifiID,
			Site:    sm.site,
			Members: snap.members,
			IPv6:    sm.ipv6,
		}); err != nil {
			sm.log.Warn().Err(err).Str("shard", snap.name).Msg("failed to update bbolt group cache")
		}

		// Capture callback, fire after loop with no lock held
		var pendingCB func()
		if wasCreating && sm.onActivated != nil {
			cb := sm.onActivated
			idx := snap.shard.Index
			id := snap.shard.ID
			pendingCB = func() { cb(ctx, idx, id) }
		}

		// Fire callback outside loop with no lock held
		if pendingCB != nil {
			pendingCB()
		}
	}

	return firstErr
}

// PrunableTail returns the last shard's UniFi ID and index if it is pruneable:
// empty (0 members) AND not the only shard (len > 1).
// Returns ok=false if pruning is not applicable.
// PrunableTail returns the last shard's UniFi ID and index if it is pruneable:
// empty (0 members) AND not the only shard (len > 1) AND Active (not Pending/Draining).
// Returns ok=false if pruning is not applicable.
func (sm *ShardManager) PrunableTail() (unifiID string, shardIdx int, ok bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	family := sm.families[sm.family]

	if len(family.Shards) <= 1 {
		return "", -1, false
	}

	last := family.Shards[len(family.Shards)-1]
	// Only prune Active shards that are empty; skip Pending and Draining
	if last.State != ShardStateActive || last.IPs.Len() > 0 {
		return "", -1, false
	}

	return last.ID, last.Index, true
}

// RemoveTail removes the last shard from in-memory slice and bbolt.
// Call only after the API group has been successfully deleted.
func (sm *ShardManager) RemoveTail() error {
	sm.mu.Lock()
	family := sm.familyStateLocked(sm.family)
	n := len(family.Shards)
	if n == 0 {
		sm.mu.Unlock()
		return nil
	}
	last := family.Shards[n-1]
	name, nameErr := sm.namer.GroupName(NameData{Family: Family(sm.ipv6), Index: last.Index, Site: sm.site})
	for ip, owner := range family.ipOwner {
		if owner == last.Index {
			delete(family.ipOwner, ip)
		}
	}
	family.Shards = family.Shards[:n-1]
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
	family := sm.families[sm.family]
	_, ok := family.ipOwner[ip]
	return ok
}

// AllMembers returns all IPs across all shards.
func (sm *ShardManager) AllMembers() []string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	family := sm.families[sm.family]
	var all []string
	for _, s := range family.Shards {
		all = append(all, s.IPs.Members()...)
	}
	return all
}

// allocShard allocates an in-memory Pending shard without making any UniFi API or bbolt calls.
// The shard will transition from Pending to Active during the first flush when syncShard() posts to UniFi.
func (sm *ShardManager) allocShard(idx int) *Shard {
	name, _ := sm.namer.GroupName(NameData{Family: Family(sm.ipv6), Index: idx, Site: sm.site})
	// Ignore error because we'll get the same error later if it's a real problem
	// (e.g., in syncShard or FlushDirty when we try to use the name).
	return &Shard{
		ID:     "",                    // Empty ID indicates Pending state
		Name:   name,
		Index:  idx,
		Family: Family(sm.ipv6),
		IPs:    NewIPSet(),
		State:  ShardStatePending,
	}
}

// doCreateUniFiGroup performs the POST API call to create a group (TML in zone mode,
// FirewallGroup in legacy mode) with the placeholder item.
// Returns the created group's ID.
func (sm *ShardManager) doCreateUniFiGroup(ctx context.Context, name string) (string, error) {
	objectKind := sm.shardObjectKind()

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
			Items:     tmlPlaceholderItems(sm.ipv6), // API requires non-empty items on create
		})
		if err != nil {
			var conflict *controller.ErrConflict
			if errors.As(err, &conflict) {
				if id := sm.findExistingTMLByName(ctx, name); id != "" {
					sm.log.Warn().Str("shard", name).Str("id", id).
						Msg("TML already exists (409 conflict); recovering existing ID")
					return id, nil
				}
			}
			return "", fmt.Errorf("create %s %s: %w", objectKind, name, err)
		}
		if created.ID == "" {
			return "", fmt.Errorf("create %s %s: API returned empty ID", objectKind, name)
		}
		return created.ID, nil
	}

	groupType := "address-group"
	if sm.ipv6 {
		groupType = "ipv6-address-group"
	}
	placeholder := TMLPlaceholderV4
	if sm.ipv6 {
		placeholder = TMLPlaceholderV6
	}
	created, err := sm.ctrl.CreateFirewallGroup(ctx, sm.site, controller.FirewallGroup{
		Name:         name,
		GroupType:    groupType,
		GroupMembers: []string{placeholder},
	})
	if err != nil {
		var conflict *controller.ErrConflict
		if errors.As(err, &conflict) {
			if id := sm.findExistingGroupByName(ctx, name); id != "" {
				sm.log.Warn().Str("shard", name).Str("id", id).
					Msg("firewall group already exists (409 conflict); recovering existing ID")
				return id, nil
			}
		}
		return "", fmt.Errorf("create %s %s: %w", objectKind, name, err)
	}
	if created.ID == "" {
		return "", fmt.Errorf("create %s %s: API returned empty ID", objectKind, name)
	}
	return created.ID, nil
}

// createShard creates a new empty shard in UniFi and registers it in bbolt.
// In zone mode this creates a Traffic Matching List; in legacy mode a FirewallGroup.
func (sm *ShardManager) createShard(ctx context.Context, idx int) (*Shard, error) {
	name, err := sm.namer.GroupName(NameData{Family: Family(sm.ipv6), Index: idx, Site: sm.site})
	if err != nil {
		return nil, err
	}

	objectKind := sm.shardObjectKind()

	if sm.dryRun {
		sm.log.Info().Str("name", name).Bool("ipv6", sm.ipv6).Int("shard", idx).
			Msgf("[DRY-RUN] would create %s", objectKind)
		shard := &Shard{ID: "dry-run-no-id", Name: name, Index: idx, Family: Family(sm.ipv6), IPs: NewIPSet(), State: ShardStateActive}
		shard.IPs.MarkClean()
		return shard, nil
	}

	createdID, err := sm.doCreateUniFiGroup(ctx, name)
	if err != nil {
		return nil, err
	}

	shard := &Shard{ID: createdID, Name: name, Index: idx, Family: Family(sm.ipv6), IPs: NewIPSet(), State: ShardStateActive}
	shard.IPs.MarkClean()

	if err := sm.store.SetGroup(name, storage.GroupRecord{
		UnifiID: createdID,
		Site:    sm.site,
		Members: []string{},
		IPv6:    sm.ipv6,
	}); err != nil {
		sm.log.Warn().Err(err).Str("shard", name).Msg("failed to cache new shard in bbolt")
	}

	sm.log.Info().Str("name", name).Str("id", createdID).Msgf("created %s", objectKind)
	return shard, nil
}

// GroupIDs returns all UniFi IDs of the managed shards.
// GroupIDs returns the UniFi IDs of all non-Pending shards (Active and Draining).
// Pending shards (not yet created in UniFi) have empty IDs and are filtered out.
// This is safe because all callers (manager.go, legacy.go, zone.go) need only Active/Draining
// shard IDs for rule/policy provisioning or deletion.
func (sm *ShardManager) GroupIDs() []string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	family := sm.families[sm.family]
	ids := make([]string, 0, len(family.Shards))
	for _, s := range family.Shards {
		// Skip Pending shards (ID is empty and they don't exist in UniFi yet)
		if s.State != ShardStatePending && s.ID != "" {
			ids = append(ids, s.ID)
		}
	}
	return ids
}

func (sm *ShardManager) updateMetricsLocked() {
	family := sm.families[sm.family]
	familyName := Family(sm.ipv6)
	for i, s := range family.Shards {
		name, _ := sm.namer.GroupName(NameData{Family: familyName, Index: i, Site: sm.site})
		count := float64(s.IPs.Len())
		metrics.FirewallGroupSize.WithLabelValues(familyName, name, sm.site).Set(count)
		if sm.shardLimit > 0 {
			metrics.ShardOccupancy.WithLabelValues(familyName, name, sm.site).Set(count / float64(sm.shardLimit))
		}
	}
}

// countDirty returns the number of shards that currently have dirty IPs.
func (sm *ShardManager) countDirty() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	managed := sm.families[sm.family]
	if managed == nil {
		return 0
	}
	n := 0
	for _, shard := range managed.Shards {
		if shard.IPs.IsDirty() {
			n++
		}
	}
	return n
}

// syncAllFamilies flushes dirty shards for every family managed by this ShardManager.
// Takes a snapshot of shard pointers under lock to avoid data races with concurrent AddIP calls
// that may append to the Shards slice. Returns the first error encountered (subsequent errors
// are still attempted and logged internally by syncShard).
func (sm *ShardManager) syncAllFamilies(ctx context.Context) error {
	// Snapshot shard pointers under read lock.
	// Individual shard operations (IPSet) are internally lock-protected,
	// so iterating snapshots outside the lock is safe.
	sm.mu.RLock()
	managed := sm.families[sm.family]
	var shards []*Shard
	if managed != nil {
		shards = make([]*Shard, len(managed.Shards))
		copy(shards, managed.Shards)
	}
	sm.mu.RUnlock()

	var firstErr error
	for _, shard := range shards {
		if err := sm.syncShard(ctx, shard); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (sm *ShardManager) syncShard(ctx context.Context, shard *Shard) error {
	ips, dirty := shard.IPs.PeekDirty()
	if !dirty {
		return nil
	}

	// Snapshot State under the read lock to avoid races with concurrent AddIP/Rebalance
	// that read or write shard.State under sm.mu.Lock().
	sm.mu.RLock()
	state := shard.State
	sm.mu.RUnlock()

	// Skip Draining shards; they are handled by drainDraining.
	if state == ShardStateDraining {
		return nil
	}

	// If the shard is Pending and has no IPs, don't create it in UniFi yet.
	if state == ShardStatePending && len(ips) == 0 {
		return nil
	}

	start := time.Now()
	shardLabel := fmt.Sprintf("%d", shard.Index)
	metrics.ShardIPCount.WithLabelValues(shard.Family, shardLabel, sm.site).Set(float64(len(ips)))

	if sm.dryRun {
		sm.log.Info().Str("shard", shard.Name).Int("member_count", len(ips)).
			Msgf("[DRY-RUN] would sync %s", sm.shardObjectKind())
		shard.IPs.CommitClean()
		// In dry-run, transition Pending to Active for consistency
		var pendingCB func()
		if state == ShardStatePending {
			sm.mu.Lock()
			shard.State = ShardStateActive
			sm.mu.Unlock()
			if sm.onActivated != nil {
				cb := sm.onActivated
				idx := shard.Index
				id := shard.ID
				pendingCB = func() { cb(ctx, idx, id) }
			}
		}
		// Fire callback with no lock held
		if pendingCB != nil {
			pendingCB()
		}
		return nil
	}

	// Skip the PUT if content is unchanged from last successful flush.
	// This avoids sending large JSON payloads when the janitor marks a shard dirty
	// but no IPs actually changed (e.g., TTL-only expiry with no removal).
	// Only applicable to Active shards — Pending shards must always be flushed.
	if state == ShardStateActive && !shard.IPs.HasChangedFromFlushed() {
		shard.IPs.MarkClean() // clear dirty flag; lastFlushed snapshot remains valid
		sm.log.Debug().Str("shard", shard.Name).Msg("shard skipped: no change from last flush")
		return nil
	}

	// Pending→Active transition: POST to create the group first
	wasCreating := false
	if state == ShardStatePending {
		createdID, err := sm.doCreateUniFiGroup(ctx, shard.Name)
		if err != nil {
			sm.log.Error().Err(err).Str("shard", shard.Name).Msg("failed to create shard in UniFi")
			return err
		}
		shard.ID = createdID
		wasCreating = true
		// Cache the newly created shard with empty members (will be updated by the PUT below)
		if err := sm.store.SetGroup(shard.Name, storage.GroupRecord{
			UnifiID: createdID,
			Site:    sm.site,
			Members: []string{},
			IPv6:    sm.ipv6,
		}); err != nil {
			sm.log.Warn().Err(err).Str("shard", shard.Name).Msg("failed to cache new shard in bbolt after POST")
		}
		sm.log.Debug().Str("shard", shard.Name).Str("id", createdID).Msg("created shard in UniFi")
	}

	sort.Strings(ips)

	realIPCount := len(ips) // save before placeholder substitution

	// UniFi API rejects empty items arrays on both create and update (HTTP 400).
	// Substitute the RFC 5737/3849 placeholder when no real bans exist.
	if len(ips) == 0 {
		if sm.ipv6 {
			ips = []string{TMLPlaceholderV6}
		} else {
			ips = []string{TMLPlaceholderV4}
		}
	}

	groupType := "address-group"
	if sm.ipv6 {
		groupType = "ipv6-address-group"
	}

	var putErr error
	if sm.mode == "zone" {
		items := make([]controller.TrafficMatchingListItem, 0, len(ips))
		for _, ip := range ips {
			items = append(items, controller.TrafficMatchingListItem{Type: "IP_ADDRESS", Value: ip})
		}
		putErr = sm.ctrl.UpdateTrafficMatchingList(ctx, sm.site, controller.TrafficMatchingList{
			ID:        shard.ID,
			Name:      shard.Name,
			Type:      tmlTypeForFamily(shard.Family),
			GroupType: groupType,
			Items:     items,
		})
	} else {
		putErr = sm.ctrl.UpdateFirewallGroup(ctx, sm.site, controller.FirewallGroup{
			ID:           shard.ID,
			Name:         shard.Name,
			GroupType:    groupType,
			GroupMembers: ips,
		})
	}

	if putErr != nil {
		metrics.ShardSyncTotal.WithLabelValues(shard.Family, shardLabel, sm.site, "error").Inc()
		metrics.ShardSyncDuration.WithLabelValues(shard.Family, shardLabel, sm.site).Observe(time.Since(start).Seconds())

		// Propagate rate-limit signal to manager before logging so the manager can
		// suppress further flushes during the Retry-After window.
		var rl *controller.ErrRateLimit
		if errors.As(putErr, &rl) && sm.onRateLimit != nil {
			sm.onRateLimit(rl.RetryAfter)
			sm.log.Warn().Dur("retry_after", rl.RetryAfter).Str("shard", shard.Name).
				Msg("rate limited by controller; backing off")
			return putErr
		}

		// If the object was deleted from UniFi externally, reset to Pending so
		// it gets re-created on the next flush.
		var nf *controller.ErrNotFound
		if errors.As(putErr, &nf) {
			sm.log.Warn().Str("shard", shard.Name).Str("shard_id", shard.ID).
				Msg("shard object not found in UniFi (externally deleted?); resetting to Pending for re-creation")
			sm.mu.Lock()
			shard.State = ShardStatePending
			shard.ID = ""
			sm.mu.Unlock()
			_ = sm.store.SetGroup(shard.Name, storage.GroupRecord{Site: sm.site, IPv6: sm.ipv6})
			return nil
		}

		sm.log.Error().Err(putErr).Str("shard", shard.Name).Str("shard_id", shard.ID).Int("ip_count", len(ips)).
			Msg("shard sync failed, will retry next tick")
		if sm.onSyncError != nil {
			sm.onSyncError()
		}
		return putErr
	}

	shard.IPs.CommitFlushed()
	if err := sm.store.SetGroup(shard.Name, storage.GroupRecord{
		UnifiID: shard.ID,
		Site:    sm.site,
		Members: ips,
		IPv6:    sm.ipv6,
	}); err != nil {
		sm.log.Warn().Err(err).Str("shard", shard.Name).Msg("failed to update bbolt group cache after sync")
	}

	// Pending→Active transition: mark as Active and fire activation callback.
	// Lock briefly to protect shard.State against concurrent readers (e.g. AddIP).
	var pendingCB func()
	if wasCreating {
		sm.mu.Lock()
		shard.State = ShardStateActive
		sm.mu.Unlock()
		if sm.onActivated != nil {
			cb := sm.onActivated
			idx := shard.Index
			id := shard.ID
			pendingCB = func() { cb(ctx, idx, id) }
		}
	}

	// Fire callback with no lock held
	if pendingCB != nil {
		pendingCB()
	}

	if sm.onSyncSuccess != nil {
		sm.onSyncSuccess()
	}
	metrics.ShardSyncTotal.WithLabelValues(shard.Family, shardLabel, sm.site, "ok").Inc()
	metrics.ShardSyncDuration.WithLabelValues(shard.Family, shardLabel, sm.site).Observe(time.Since(start).Seconds())
	sm.log.Debug().Str("shard", shard.Name).Int("count", len(ips)).Msg("shard synced")
	if realIPCount > 0 {
		sm.log.Info().
			Str("shard", shard.Name).
			Int("ip_count", realIPCount).
			Str("site", sm.site).
			Msg("shard flushed to UniFi")
	}
	return nil
}

// findExistingTMLByName queries the UniFi API for a TML with the given name.
// Used for 409 conflict recovery: if CreateTrafficMatchingList returns ErrConflict,
// the TML already exists and we can recover its ID to continue without re-creating.
func (sm *ShardManager) findExistingTMLByName(ctx context.Context, name string) string {
	tmls, err := sm.ctrl.ListTrafficMatchingLists(ctx, sm.site)
	if err != nil {
		return ""
	}
	for _, t := range tmls {
		if t.Name == name {
			return t.ID
		}
	}
	return ""
}

// findExistingGroupByName queries the UniFi API for a firewall group with the given name.
// Used for 409 conflict recovery in legacy mode.
func (sm *ShardManager) findExistingGroupByName(ctx context.Context, name string) string {
	groups, err := sm.ctrl.ListFirewallGroups(ctx, sm.site)
	if err != nil {
		return ""
	}
	for _, g := range groups {
		if g.Name == name {
			return g.ID
		}
	}
	return ""
}

func tmlTypeForFamily(family string) string {
	if family == "v6" {
		return "IPV6_ADDRESSES"
	}
	return "IPV4_ADDRESSES"
}

// Rebalance merges under-filled Active shards into larger ones to minimise
// the number of live TMLs and firewall policies.
// Returns the number of shards transitioned to Draining.
// If ShardMergeThreshold is -1, rebalancing is disabled and 0 is returned.
// Call before syncAllFamilies so moved IPs are flushed together with the target shard.
func (sm *ShardManager) Rebalance(ctx context.Context) int {
	threshold := sm.mergeThreshold
	if threshold < 0 {
		return 0 // rebalancing disabled
	}
	if threshold == 0 {
		threshold = sm.shardLimit / 2
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	family := sm.familyStateLocked(sm.family)
	merged := 0

	for {
		// Find the Active non-anchor shard with the lowest IP count at or below threshold.
		donorIdx := -1
		donorCount := threshold + 1

		for i, s := range family.Shards {
			if s.State != ShardStateActive {
				continue
			}
			if s.Index == 0 {
				continue // anchor shard never donates
			}
			count := s.IPs.Len()
			if count > threshold {
				continue
			}
			if count < donorCount {
				donorCount = count
				donorIdx = i
			}
		}

		if donorIdx < 0 {
			break // no eligible donor
		}

		donor := family.Shards[donorIdx]
		donorIPs := donor.IPs.Members() // snapshot while holding sm.mu

		// Find the first Active shard (other than donor) that has room for all donor IPs.
		targetIdx := -1
		for i, s := range family.Shards {
			if i == donorIdx {
				continue
			}
			if s.State != ShardStateActive {
				continue
			}
			if s.IPs.Len()+len(donorIPs) <= sm.shardLimit {
				targetIdx = i
				break
			}
		}

		if targetIdx < 0 {
			break // donor can't fit anywhere
		}

		target := family.Shards[targetIdx]

		// Move all IPs from donor into target and update ownership map.
		for _, ip := range donorIPs {
			target.IPs.Add(ip) // marks target dirty
			family.ipOwner[ip] = target.Index
		}

		// Clear donor and mark as Draining (syncShard skips Draining shards).
		donor.IPs.Replace(nil)
		donor.State = ShardStateDraining

		sm.log.Info().
			Str("site", sm.site).
			Int("donor_shard", donor.Index).
			Str("donor_id", donor.ID).
			Int("donor_ips", donorCount).
			Int("target_shard", target.Index).
			Str("target_id", target.ID).
			Int("target_ips_after", target.IPs.Len()).
			Msg("shard rebalance: merging donor into target")

		merged++
	}

	return merged
}

// drainDraining processes all shards in Draining state, deleting their UniFi objects
// and removing them from in-memory state.
// Should be called after syncAllFamilies so target shards are flushed before donors are deleted.
func (sm *ShardManager) drainDraining(ctx context.Context) {
	sm.mu.RLock()
	family := sm.familyStateLocked(sm.family)
	var draining []*Shard
	for _, s := range family.Shards {
		if s.State == ShardStateDraining {
			draining = append(draining, s)
		}
	}
	sm.mu.RUnlock()

	for _, shard := range draining {
		sm.drainShard(ctx, shard)
	}
}

// drainShard deletes a single Draining shard from UniFi and removes it from memory.
// On API error the shard remains Draining and will be retried on the next tick.
func (sm *ShardManager) drainShard(ctx context.Context, shard *Shard) {
	sm.log.Debug().
		Str("shard", shard.Name).
		Str("shard_id", shard.ID).
		Bool("onDrainedFired", shard.onDrainedFired).
		Msg("drainShard: attempt")

	// 1. Delete policies/rules first — UniFi rejects group deletion while referenced.
	// Gate on onDrainedFired so that if DeleteShardObject fails and this shard is
	// retried on the next tick, we do not attempt a duplicate policy/rule deletion.
	if sm.onDrained != nil && !shard.onDrainedFired {
		sm.onDrained(ctx, shard.Index, shard.ID)
		shard.onDrainedFired = true
	}

	// 2. Pace API calls with the configured shard delay.
	if sm.flushDelay > 0 {
		select {
		case <-time.After(sm.flushDelay):
		case <-ctx.Done():
			return
		}
	}

	// 3. Delete the UniFi TML / firewall group object.
	if shard.ID != "" {
		if err := sm.DeleteShardObject(ctx, shard.ID); err != nil {
			sm.log.Error().Err(err).
				Str("shard", shard.Name).Str("shard_id", shard.ID).
				Msg("drainShard: failed to delete UniFi object; will retry on next tick")
			return // leave in Draining state for retry
		}
	}

	// 4. Remove from bbolt.
	if err := sm.store.DeleteGroup(shard.Name); err != nil {
		sm.log.Warn().Err(err).Str("shard", shard.Name).
			Msg("drainShard: failed to delete from bbolt")
	}

	// 5. Splice the shard out of the in-memory slice (verify state under lock).
	sm.mu.Lock()
	family := sm.familyStateLocked(sm.family)
	for pos, s := range family.Shards {
		if s.Index == shard.Index && s.State == ShardStateDraining {
			family.Shards = append(family.Shards[:pos], family.Shards[pos+1:]...)
			break
		}
	}
	// Clean up any stale ipOwner entries (defensive; Rebalance updates these already).
	for ip, ownerIdx := range family.ipOwner {
		if ownerIdx == shard.Index {
			delete(family.ipOwner, ip)
		}
	}
	sm.mu.Unlock()

	// 6. Increment rebalanced-shards metric.
	metrics.ShardsRebalanced.WithLabelValues(sm.family, sm.site).Inc()

	sm.log.Info().
		Str("site", sm.site).
		Str("shard", shard.Name).
		Str("shard_id", shard.ID).
		Int("shard_idx", shard.Index).
		Msg("drainShard: drained shard removed from UniFi and memory")
}

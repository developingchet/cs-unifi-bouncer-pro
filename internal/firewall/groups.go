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

// Shard represents a single Traffic Matching List shard in zone mode.
// In legacy mode, it represents a firewall group shard.
type Shard struct {
	ID     string // TML UUID (integration v1) or firewall group ID (legacy)
	Name   string // "crowdsec-block-v4-0" or similar
	Index  int    // shard number (0, 1, 2, ...)
	Family string // "v4" or "v6"
	IPs    *IPSet // in-memory authoritative IP set
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
				shard = &Shard{ID: tml.ID, Name: tml.Name, Index: idx, Family: Family(sm.ipv6), IPs: NewIPSet()}
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
				foundInAPI = true
			}
		} else {
			if apiGroup, exists := apiGroupByID[rec.UnifiID]; exists {
				members := make([]string, len(apiGroup.GroupMembers))
				copy(members, apiGroup.GroupMembers)
				shard = &Shard{ID: rec.UnifiID, Name: name, Index: idx, Family: Family(sm.ipv6), IPs: NewIPSet()}
				shard.IPs.Replace(members)
				shard.IPs.MarkClean()
				foundInAPI = true
			}
		}

		if !foundInAPI {
			shard, err = sm.createShard(ctx, idx)
			if err != nil {
				return err
			}
			if len(rec.Members) > 0 {
				// Keep dirty so old members are restored on next sync tick.
				shard.IPs.Replace(rec.Members)
			}
		}

		family.Shards = append(family.Shards, shard)
		idx++
	}

	if len(family.Shards) == 0 {
		shard, err := sm.createShard(ctx, 0)
		if err != nil {
			return err
		}
		family.Shards = append(family.Shards, shard)
	}

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
// If all shards are full, a new shard is created.
func (sm *ShardManager) AddIP(ctx context.Context, ip, ipFamily string) error {
	sm.mu.Lock()
	family := sm.familyStateLocked(ipFamily)

	if _, owned := family.ipOwner[ip]; owned {
		sm.mu.Unlock()
		return nil
	}

	for _, shard := range family.Shards {
		if shard.IPs.Capacity(sm.shardLimit) > 0 {
			shard.IPs.Add(ip)
			family.ipOwner[ip] = shard.Index
			sm.updateMetricsLocked()
			sm.mu.Unlock()
			return nil
		}
	}

	nextIndex := len(family.Shards)
	sm.mu.Unlock()

	shard, err := sm.createShard(ctx, nextIndex)
	if err != nil {
		return fmt.Errorf("create shard for family %s: %w", ipFamily, err)
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()
	family = sm.familyStateLocked(ipFamily)

	if existing, _ := sm.findShardByIndexLocked(family, nextIndex); existing == nil {
		family.Shards = append(family.Shards, shard)
		sort.Slice(family.Shards, func(i, j int) bool {
			return family.Shards[i].Index < family.Shards[j].Index
		})
	}

	if _, owned := family.ipOwner[ip]; owned {
		sm.updateMetricsLocked()
		return nil
	}

	for _, s := range family.Shards {
		if s.IPs.Capacity(sm.shardLimit) > 0 {
			s.IPs.Add(ip)
			family.ipOwner[ip] = s.Index
			sm.updateMetricsLocked()
			return nil
		}
	}

	return fmt.Errorf("no available shard capacity for family %s", ipFamily)
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
		ips, dirty := family.Shards[i].IPs.PeekDirty()
		if !dirty {
			continue
		}

		members := make([]string, 0, len(ips))
		for _, m := range ips {
			members = append(members, m)
		}
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

		name, err := sm.namer.GroupName(NameData{Family: Family(sm.ipv6), Index: family.Shards[i].Index, Site: sm.site})
		if err != nil {
			sm.mu.Unlock()
			return err
		}

		snapshots = append(snapshots, flushSnapshot{
			idx:     i,
			unifiID: family.Shards[i].ID,
			name:    name,
			members: members,
		})
		// Clear dirty flag now so Add/Remove can proceed.
		family.Shards[i].IPs.MarkClean()
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
	family := sm.families[sm.family]

	if len(family.Shards) <= 1 {
		return "", -1, false
	}

	last := family.Shards[len(family.Shards)-1]
	if last.IPs.Len() > 0 {
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
		shard := &Shard{ID: "dry-run-no-id", Name: name, Index: idx, Family: Family(sm.ipv6), IPs: NewIPSet()}
		shard.IPs.MarkClean()
		return shard, nil
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
			Items:     tmlPlaceholderItems(sm.ipv6), // API requires non-empty items on create
		})
		if err != nil {
			return nil, fmt.Errorf("create shard %s: %w", name, err)
		}
		createdID = created.ID
		if createdID == "" {
			return nil, fmt.Errorf("create shard %s: API returned empty ID", name)
		}
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
			return nil, fmt.Errorf("create shard %s: %w", name, err)
		}
		createdID = created.ID
		if createdID == "" {
			return nil, fmt.Errorf("create shard %s: API returned empty ID", name)
		}
	}

	shard := &Shard{ID: createdID, Name: name, Index: idx, Family: Family(sm.ipv6), IPs: NewIPSet()}
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
func (sm *ShardManager) GroupIDs() []string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	family := sm.families[sm.family]
	ids := make([]string, 0, len(family.Shards))
	for _, s := range family.Shards {
		ids = append(ids, s.ID)
	}
	return ids
}

func (sm *ShardManager) updateMetricsLocked() {
	family := sm.families[sm.family]
	familyName := Family(sm.ipv6)
	for i, s := range family.Shards {
		name, _ := sm.namer.GroupName(NameData{Family: familyName, Index: i, Site: sm.site})
		metrics.FirewallGroupSize.WithLabelValues(familyName, name, sm.site).Set(float64(s.IPs.Len()))
	}
}

func (sm *ShardManager) updateMetrics() {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	sm.updateMetricsLocked()
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
// that may append to the Shards slice.
func (sm *ShardManager) syncAllFamilies(ctx context.Context) {
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

	for _, shard := range shards {
		sm.syncShard(ctx, shard)
	}
}

func (sm *ShardManager) syncShard(ctx context.Context, shard *Shard) {
	ips, dirty := shard.IPs.PeekDirty()
	if !dirty {
		return
	}

	start := time.Now()
	shardLabel := fmt.Sprintf("%d", shard.Index)
	metrics.ShardIPCount.WithLabelValues(shard.Family, shardLabel, sm.site).Set(float64(len(ips)))

	if sm.dryRun {
		sm.log.Info().Str("shard", shard.Name).Int("member_count", len(ips)).
			Msgf("[DRY-RUN] would sync %s", sm.shardObjectKind())
		shard.IPs.CommitClean()
		return
	}

	sort.Strings(ips)

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
		sm.log.Error().Err(putErr).Str("shard", shard.Name).Str("shard_id", shard.ID).Int("ip_count", len(ips)).
			Msg("shard sync failed, will retry next tick")
		return
	}

	shard.IPs.CommitClean()
	if err := sm.store.SetGroup(shard.Name, storage.GroupRecord{
		UnifiID: shard.ID,
		Site:    sm.site,
		Members: ips,
		IPv6:    sm.ipv6,
	}); err != nil {
		sm.log.Warn().Err(err).Str("shard", shard.Name).Msg("failed to update bbolt group cache after sync")
	}
	metrics.ShardSyncTotal.WithLabelValues(shard.Family, shardLabel, sm.site, "ok").Inc()
	metrics.ShardSyncDuration.WithLabelValues(shard.Family, shardLabel, sm.site).Observe(time.Since(start).Seconds())
	sm.log.Debug().Str("shard", shard.Name).Int("count", len(ips)).Msg("shard synced")
}

func tmlTypeForFamily(family string) string {
	if family == "v6" {
		return "IPV6_ADDRESSES"
	}
	return "IPV4_ADDRESSES"
}

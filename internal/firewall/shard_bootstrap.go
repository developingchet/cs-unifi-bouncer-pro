package firewall

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
)

// apiShardObjects is one listing of the controller's shard objects, keyed by
// name. Only the map for the manager's mode is populated.
type apiShardObjects struct {
	groups map[string]controller.FirewallGroup
	tmls   map[string]controller.TrafficMatchingList
}

// EnsureShards bootstraps group shards: loads from bbolt cache, then reconciles with API.
func (sm *ShardManager) EnsureShards(ctx context.Context) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	family := sm.fam
	family.Shards = family.Shards[:0]
	clear(family.ipOwner)

	// Load all known group records from bbolt.
	allGroups, err := sm.store.ListGroups()
	if err != nil {
		return fmt.Errorf("list groups from store: %w", err)
	}

	api, err := sm.listAPIShardObjects(ctx)
	if err != nil {
		return err
	}

	candidates, indices, known, err := sm.collectCachedCandidates(allGroups)
	if err != nil {
		return err
	}
	sm.addAPICandidates(api, candidates)
	ordered, err := sm.resolveShardIndices(candidates, indices, known)
	if err != nil {
		return err
	}

	for _, idx := range ordered {
		shard, err := sm.loadShardLocked(idx, allGroups, api)
		if err != nil {
			return err
		}
		// Only add to family.Shards if shard was created (not an orphan)
		if shard != nil {
			family.Shards = append(family.Shards, shard)
		}
	}

	// Lazy shard creation: do not create an initial shard if none are loaded from bbolt.
	// Shards are created only when the first IP is assigned to them (via AddIP).
	// This prevents empty shards from existing in UniFi unnecessarily.

	sort.Slice(family.Shards, func(i, j int) bool {
		return family.Shards[i].Index < family.Shards[j].Index
	})

	sm.assignOwnersLocked()
	sm.splitOversizedLocked()
	sm.updateMetricsLocked()
	return nil
}

// splitOversizedLocked moves members beyond the shard limit out of each
// loaded shard, so lowering the capacity takes effect on restart. The moved
// members go to shards with room, or to new Pending shards. Callers hold sm.mu.
func (sm *ShardManager) splitOversizedLocked() {
	// range reads the slice once, so shards allocated below are not revisited.
	for _, shard := range sm.fam.Shards {
		if shard.IPs.Len() <= sm.shardLimit {
			continue
		}
		members := shard.IPs.Members()
		sort.Strings(members)
		excess := members[sm.shardLimit:]
		for _, ip := range excess {
			sm.removeIPLocked(ip)
		}
		for _, ip := range excess {
			sm.addIPLocked(ip)
		}
		sm.log.Warn().Str("site", sm.site).Str("shard", shard.Name).
			Int("moved", len(excess)).Int("limit", sm.shardLimit).
			Msg("shard holds more members than its capacity; moved the excess to other shards")
	}
}

// listAPIShardObjects fetches the current shard objects from UniFi: traffic
// matching lists in zone mode, firewall groups otherwise.
func (sm *ShardManager) listAPIShardObjects(ctx context.Context) (apiShardObjects, error) {
	var api apiShardObjects
	if sm.mode == "zone" {
		tmls, err := sm.ctrl.ListTrafficMatchingLists(ctx, sm.site)
		if err != nil {
			return api, fmt.Errorf("list traffic matching lists from API: %w", err)
		}
		api.tmls = make(map[string]controller.TrafficMatchingList, len(tmls))
		for _, t := range tmls {
			api.tmls[t.Name] = t
		}
		return api, nil
	}
	apiGroups, err := sm.ctrl.ListFirewallGroups(ctx, sm.site)
	if err != nil {
		return api, fmt.Errorf("list firewall groups from API: %w", err)
	}
	api.groups = make(map[string]controller.FirewallGroup, len(apiGroups))
	for _, g := range apiGroups {
		api.groups[g.Name] = g
	}
	return api, nil
}

// collectCachedCandidates gathers this site and family's cached group names,
// the indices already known from their records, and the names those indices
// render to. Older databases keyed groups only by name; this site's records
// are moved to site-scoped keys (in the store and in allGroups) before
// reconciling names shared by multiple sites.
func (sm *ShardManager) collectCachedCandidates(allGroups map[string]storage.GroupRecord) (
	candidates map[string]struct{}, indices map[int]struct{}, known map[string]struct{}, err error) {
	candidates = make(map[string]struct{})
	indices = make(map[int]struct{})
	known = make(map[string]struct{})
	for key, rec := range allGroups {
		if rec.Site != sm.site || rec.IPv6 != sm.ipv6 {
			continue
		}
		name := cacheName(key)
		if key == name {
			scoped := cacheKey(sm.site, name)
			if _, exists := allGroups[scoped]; !exists {
				if err := sm.store.SetGroup(scoped, rec); err != nil {
					return nil, nil, nil, fmt.Errorf("migrate group %s: %w", name, err)
				}
				allGroups[scoped] = rec
			}
			if err := sm.store.DeleteGroup(key); err != nil {
				return nil, nil, nil, fmt.Errorf("remove old group key %s: %w", name, err)
			}
			delete(allGroups, key)
		}
		candidates[name] = struct{}{}
		if rec.Index > 0 {
			rendered, err := sm.namer.GroupName(NameData{Family: sm.family, Index: rec.Index, Site: sm.site})
			if err == nil && rendered == name {
				indices[rec.Index] = struct{}{}
				known[name] = struct{}{}
			}
		}
	}
	return candidates, indices, known, nil
}

// addAPICandidates adds the names of controller objects that match this
// family's object type and the configured name prefix.
func (sm *ShardManager) addAPICandidates(api apiShardObjects, candidates map[string]struct{}) {
	for name, tml := range api.tmls {
		if tml.Type != "" && tml.Type != tmlTypeForFamily(sm.family) {
			continue
		}
		if prefix := sm.namer.GroupPrefix(); prefix != "" && !strings.HasPrefix(name, prefix) {
			continue
		}
		candidates[name] = struct{}{}
	}
	for name, group := range api.groups {
		groupType := "address-group"
		if sm.ipv6 {
			groupType = "ipv6-address-group"
		}
		if group.GroupType != "" && group.GroupType != groupType {
			continue
		}
		if prefix := sm.namer.GroupPrefix(); prefix != "" && !strings.HasPrefix(name, prefix) {
			continue
		}
		candidates[name] = struct{}{}
	}
}

// resolveShardIndices maps candidate names to shard indices, adds them to
// indices, and returns all indices in ascending order.
func (sm *ShardManager) resolveShardIndices(candidates map[string]struct{}, indices map[int]struct{},
	known map[string]struct{}) ([]int, error) {
	unresolved := make(map[string]struct{})
	for name := range candidates {
		if _, found := known[name]; found {
			continue
		}
		if idx, ok := sm.shardIndexForName(name); ok {
			indices[idx] = struct{}{}
		} else {
			unresolved[name] = struct{}{}
		}
	}
	// A template may render the index without decimal digits. Match those
	// names by rendering candidate indices once for the whole API snapshot.
	for idx := 0; idx <= 10_000 && len(unresolved) > 0; idx++ {
		name, err := sm.namer.GroupName(NameData{Family: sm.family, Index: idx, Site: sm.site})
		if err != nil {
			return nil, err
		}
		if _, found := unresolved[name]; found {
			indices[idx] = struct{}{}
			delete(unresolved, name)
		}
	}
	ordered := make([]int, 0, len(indices))
	for idx := range indices {
		ordered = append(ordered, idx)
	}
	sort.Ints(ordered)
	return ordered, nil
}

// apiShardMembers returns the controller ID and real (non-placeholder)
// members of the object named name, or an empty ID if it does not exist.
func (sm *ShardManager) apiShardMembers(api apiShardObjects, name string) (apiID string, members []string) {
	if sm.mode == "zone" {
		if tml, exists := api.tmls[name]; exists {
			apiID = tml.ID
			values := make([]string, 0, len(tml.Items))
			for _, item := range tml.Items {
				values = append(values, item.Value)
			}
			members = stripPlaceholders(values)
		}
	} else {
		if apiGroup, exists := api.groups[name]; exists {
			apiID = apiGroup.ID
			members = stripPlaceholders(apiGroup.GroupMembers)
		}
	}
	return apiID, members
}

// loadShardLocked builds the shard at idx from the controller object and the
// cached record. It returns nil when there is nothing to load, or when the
// controller object holds only the placeholder, in which case it is queued as
// an orphan. Callers hold sm.mu.
func (sm *ShardManager) loadShardLocked(idx int, allGroups map[string]storage.GroupRecord,
	api apiShardObjects) (*Shard, error) {
	name, err := sm.namer.GroupName(NameData{
		Family: Family(sm.ipv6),
		Index:  idx,
		Site:   sm.site,
	})
	if err != nil {
		return nil, err
	}

	rec, cached := allGroups[cacheKey(sm.site, name)]
	if cached && (rec.IPv6 != sm.ipv6 || rec.Site != sm.site) {
		return nil, fmt.Errorf("cached group %q has mismatched site or address family", name)
	}

	var shard *Shard
	apiID, members := sm.apiShardMembers(api, name)

	switch {
	case apiID != "" && (len(members) > 0 || cached && len(rec.Members) > 0):
		shard = &Shard{ID: apiID, Name: name, Index: idx, Family: Family(sm.ipv6), IPs: NewIPSet(), State: ShardStateActive}
		if len(members) > 0 {
			shard.IPs.Replace(members)
			shard.IPs.MarkClean()
		} else {
			// Restore cached members if a previously populated group has only
			// the creation placeholder in UniFi.
			shard.IPs.Replace(rec.Members)
			members = rec.Members
		}
		if err := sm.store.SetGroup(cacheKey(sm.site, name), storage.GroupRecord{UnifiID: apiID, Site: sm.site, Index: idx, Members: members, IPv6: sm.ipv6}); err != nil {
			return nil, fmt.Errorf("cache recovered shard %s: %w", name, err)
		}
	case apiID != "":
		sm.orphanedGroups = append(sm.orphanedGroups, orphanedGroup{UnifiID: apiID, Name: name})
	case cached:
		// Allocate a Pending shard in-memory without creating in UniFi yet.
		shard = sm.allocShard(idx)
		if len(rec.Members) > 0 {
			// Keep dirty so old members are restored on next sync tick.
			shard.IPs.Replace(rec.Members)
		}
	}
	return shard, nil
}

// assignOwnersLocked rebuilds ipOwner from the loaded shards, which must be
// sorted by index. When duplicates exist across shards, the lowest-index
// shard is the keeper: duplicates are removed from higher-index shards and
// those shards are left dirty for sync. Callers hold sm.mu.
func (sm *ShardManager) assignOwnersLocked() {
	family := sm.fam
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
}

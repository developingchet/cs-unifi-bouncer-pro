package firewall

import (
	"context"
	"fmt"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
)

// stripPlaceholders returns members without the creation placeholder that
// keeps a new group or TML non-empty.
func stripPlaceholders(members []string) []string {
	out := make([]string, 0, len(members))
	for _, m := range members {
		if m == TMLPlaceholderV4 || m == TMLPlaceholderV6 {
			continue
		}
		out = append(out, m)
	}
	return out
}

// remoteMembersByID returns the controller's current members for every shard
// object of this manager's mode, keyed by UniFi ID. Placeholders are kept:
// a placeholder address can also be a real ban, so diffMembers decides.
func (sm *ShardManager) remoteMembersByID(ctx context.Context) (map[string][]string, error) {
	remote := make(map[string][]string)
	if sm.mode == "zone" {
		tmls, err := sm.ctrl.ListTrafficMatchingLists(ctx, sm.site)
		if err != nil {
			return nil, fmt.Errorf("list traffic matching lists: %w", err)
		}
		for _, t := range tmls {
			values := make([]string, 0, len(t.Items))
			for _, item := range t.Items {
				values = append(values, item.Value)
			}
			remote[t.ID] = values
		}
		return remote, nil
	}
	groups, err := sm.ctrl.ListFirewallGroups(ctx, sm.site)
	if err != nil {
		return nil, fmt.Errorf("list firewall groups: %w", err)
	}
	for _, g := range groups {
		remote[g.ID] = g.GroupMembers
	}
	return remote, nil
}

// MarkRemoteDrift compares each active shard with the controller's copy and
// marks shards whose members were changed out of band (in the UniFi UI or by
// another tool) so the next sync rewrites them. It returns how many addresses
// the controller is missing and how many it has that it should not.
//
// Without this, reconcile only compares the ban database with in-memory
// shard state, and a shard whose local state has not changed is never
// rewritten, so out-of-band removals would persist indefinitely.
func (sm *ShardManager) MarkRemoteDrift(ctx context.Context) (missing, extra int, err error) {
	remote, err := sm.remoteMembersByID(ctx)
	if err != nil {
		return 0, 0, err
	}

	sm.mu.RLock()
	defer sm.mu.RUnlock()
	family := sm.families[sm.family]
	if family == nil {
		return 0, 0, nil
	}
	for _, shard := range family.Shards {
		if shard.State != ShardStateActive || shard.ID == "" {
			continue
		}
		if shard.IPs.IsDirty() && shard.IPs.HasChangedFromFlushed() {
			continue // local changes are pending; the next sync writes the full set anyway
		}
		members, found := remote[shard.ID]
		if !found {
			// Deleted out of band; startup reconciliation recreates it.
			continue
		}
		m, e := diffMembers(shard.IPs.Members(), members)
		if m == 0 && e == 0 {
			continue
		}
		missing += m
		extra += e
		shard.IPs.MarkStale()
		sm.log.Warn().Str("site", sm.site).Str("shard", shard.Name).
			Int("missing", m).Int("unexpected", e).
			Msg("shard changed outside the bouncer; rewriting it")
	}
	return missing, extra, nil
}

// handleShardNotFound runs after a shard write returned 404. A controller that
// is shutting down or still starting answers 404 for every API path, so the
// 404 alone does not prove the object was deleted. The shard is reset for
// re-creation only when a fresh listing confirms it is gone; if it exists
// under a new ID, that ID is adopted. It reports whether the 404 was resolved;
// false means it was transient and the write should be retried as a failure.
func (sm *ShardManager) handleShardNotFound(ctx context.Context, shard *Shard) bool {
	var id string
	var err error
	if sm.mode == "zone" {
		id, err = sm.lookupTMLByName(ctx, shard.Name)
	} else {
		id, err = sm.lookupGroupByName(ctx, shard.Name)
	}
	if err != nil {
		sm.log.Warn().Err(err).Str("shard", shard.Name).
			Msg("shard write returned 404 and the controller cannot be listed; treating as transient")
		return false
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	switch {
	case id == shard.ID:
		sm.log.Warn().Str("shard", shard.Name).
			Msg("shard write returned 404 but the object still exists; controller is likely restarting")
		return false
	case id != "":
		sm.log.Warn().Str("shard", shard.Name).Str("old_id", shard.ID).Str("new_id", id).
			Msg("shard object was recreated outside the bouncer; adopting its ID")
		shard.ID = id
		shard.IPs.MarkStale()
		_ = sm.store.SetGroup(cacheKey(sm.site, shard.Name), storage.GroupRecord{
			UnifiID: id, Site: sm.site, Index: shard.Index, Members: shard.IPs.Members(), IPv6: sm.ipv6})
		return true
	}
	sm.log.Warn().Str("shard", shard.Name).Str("shard_id", shard.ID).
		Msg("shard object was deleted outside the bouncer; resetting to Pending for re-creation")
	shard.State = ShardStatePending
	shard.ID = ""
	_ = sm.store.SetGroup(cacheKey(sm.site, shard.Name), storage.GroupRecord{Site: sm.site, Index: shard.Index, IPv6: sm.ipv6})
	return true
}

// diffMembers counts entries of want absent from have, and of have absent from
// want. A leftover creation placeholder in have is not counted as extra, but a
// placeholder address that is also a real ban still counts as missing.
func diffMembers(want, have []string) (missing, extra int) {
	haveSet := make(map[string]struct{}, len(have))
	for _, ip := range have {
		haveSet[ip] = struct{}{}
	}
	for _, ip := range want {
		if _, ok := haveSet[ip]; ok {
			delete(haveSet, ip)
		} else {
			missing++
		}
	}
	for ip := range haveSet {
		if ip != TMLPlaceholderV4 && ip != TMLPlaceholderV6 {
			extra++
		}
	}
	return missing, extra
}

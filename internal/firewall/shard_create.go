package firewall

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
)

// DeleteShardObject deletes the backing UniFi object for a shard ID.
// In zone mode this deletes a Traffic Matching List; in legacy mode a FirewallGroup.
func (sm *ShardManager) DeleteShardObject(ctx context.Context, unifiID string) error {
	if sm.mode == "zone" {
		return sm.ctrl.DeleteTrafficMatchingList(ctx, sm.site, unifiID)
	}
	return sm.ctrl.DeleteFirewallGroup(ctx, sm.site, unifiID)
}

// allocShard allocates an in-memory Pending shard without making any UniFi API or bbolt calls.
// The shard will transition from Pending to Active during the first flush when syncShard() posts to UniFi.
func (sm *ShardManager) allocShard(idx int) *Shard {
	name, _ := sm.namer.GroupName(NameData{Family: Family(sm.ipv6), Index: idx, Site: sm.site})
	// Ignore error because we'll get the same error later if it's a real problem
	// (e.g., in syncShard or FlushDirty when we try to use the name).
	return &Shard{
		ID:     "", // Empty ID indicates Pending state
		Name:   name,
		Index:  idx,
		Family: Family(sm.ipv6),
		IPs:    NewIPSet(),
		State:  ShardStatePending,
	}
}

// doCreateUniFiGroup creates the shard object (a TML in zone mode, a firewall
// group in legacy mode) holding only the placeholder member, and returns its
// ID. When a create fails or answers without an ID, the object may already
// exist under this name, so it is looked up and adopted rather than created
// again on every sync. Controllers report a duplicate name inconsistently
// (409, or 400 with various messages), so any refusal is checked, except rate
// limiting and cancellation, where another request would not help.
func (sm *ShardManager) doCreateUniFiGroup(ctx context.Context, name string) (string, error) {
	objectKind := sm.shardObjectKind()
	id, err := sm.createShardObject(ctx, name)
	if err == nil && id != "" {
		return id, nil
	}
	var rateLimited *controller.ErrRateLimit
	if err != nil && (errors.As(err, &rateLimited) || ctx.Err() != nil) {
		return "", fmt.Errorf("create %s %s: %w", objectKind, name, err)
	}

	existing, lookupErr := sm.lookupShardObjectByName(ctx, name)
	switch {
	case lookupErr != nil:
		return "", fmt.Errorf("create %s %s: look up existing object: %w", objectKind, name, lookupErr)
	case existing != "":
		sm.log.Warn().Str("shard", name).Str("id", existing).
			Msg("shard object already exists on the controller; adopting it")
		return existing, nil
	case err != nil:
		return "", fmt.Errorf("create %s %s: %w", objectKind, name, err)
	default:
		return "", fmt.Errorf("create %s %s: API returned empty ID and no object with that name exists", objectKind, name)
	}
}

// createShardObject sends the create request for a shard object.
func (sm *ShardManager) createShardObject(ctx context.Context, name string) (string, error) {
	groupType := "address-group"
	if sm.ipv6 {
		groupType = "ipv6-address-group"
	}
	if sm.mode == "zone" {
		created, err := sm.ctrl.CreateTrafficMatchingList(ctx, sm.site, controller.TrafficMatchingList{
			Name:      name,
			Type:      tmlTypeForFamily(Family(sm.ipv6)),
			GroupType: groupType,
			Items:     tmlPlaceholderItems(sm.ipv6), // API requires non-empty items on create
		})
		return created.ID, err
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
	return created.ID, err
}

// lookupShardObjectByName returns the ID of the shard object named name, ""
// if there is none, or the listing error.
func (sm *ShardManager) lookupShardObjectByName(ctx context.Context, name string) (string, error) {
	if sm.mode == "zone" {
		return sm.lookupTMLByName(ctx, name)
	}
	return sm.lookupGroupByName(ctx, name)
}

const (
	createBackoffBase = 30 * time.Second
	createBackoffMax  = 30 * time.Minute
)

// createBackoffRemaining reports how long to wait before retrying a shard
// create that has failed before.
func (sm *ShardManager) createBackoffRemaining(shard *Shard) time.Duration {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return time.Until(shard.createRetryAt)
}

// recordCreateFailure counts a failed create and schedules the next attempt
// with exponential backoff, so a controller that keeps refusing the object is
// not hit every tick. The bans in the shard stay unenforced until it exists,
// which the unsynced_ips gauge reports.
func (sm *ShardManager) recordCreateFailure(shard *Shard, ipCount int, err error) {
	sm.mu.Lock()
	shard.createFailures++
	failures := shard.createFailures
	delay := createBackoffBase << min(failures-1, 6)
	delay = min(delay, createBackoffMax)
	shard.createRetryAt = time.Now().Add(delay)
	sm.mu.Unlock()

	metrics.ShardCreateFailures.WithLabelValues(shard.Family, sm.site).Inc()
	sm.log.Error().Err(err).Str("shard", shard.Name).Int("unsynced_ips", ipCount).
		Int("consecutive_failures", failures).Stringer("retry_in", delay).
		Msg("failed to create shard on the controller; its bans are not enforced until it exists")
}

// createPendingShard creates a Pending shard's controller object and caches
// it. It reports false with a nil error while create backoff is in effect,
// and false with the error when the create fails.
func (sm *ShardManager) createPendingShard(ctx context.Context, shard *Shard, ipCount int) (bool, error) {
	if wait := sm.createBackoffRemaining(shard); wait > 0 {
		sm.log.Debug().Str("shard", shard.Name).Stringer("retry_in", wait).Msg("shard create backing off after failures")
		return false, nil
	}
	createdID, err := sm.doCreateUniFiGroup(ctx, shard.Name)
	if err != nil {
		sm.recordCreateFailure(shard, ipCount, err)
		return false, err
	}
	sm.mu.Lock()
	shard.ID = createdID
	shard.createFailures = 0
	shard.createRetryAt = time.Time{}
	sm.updateMetricsLocked()
	sm.mu.Unlock()
	// Cache the newly created shard with empty members (will be updated by the PUT below)
	if err := sm.store.SetGroup(cacheKey(sm.site, shard.Name), storage.GroupRecord{
		UnifiID: createdID,
		Site:    sm.site,
		Index:   shard.Index,
		Members: []string{},
		IPv6:    sm.ipv6,
	}); err != nil {
		sm.log.Warn().Err(err).Str("shard", shard.Name).Msg("failed to cache new shard in bbolt after POST")
	}
	sm.log.Debug().Str("shard", shard.Name).Str("id", createdID).Msg("created shard in UniFi")
	return true, nil
}

// Shard objects carry no description field on either API, so the name is the
// only ownership marker. The adoption lookups below also require the shard's
// own object type, so a same-named object of another kind (a port list, a
// group of the other address family) is never taken over and overwritten.

// lookupTMLByName returns the ID of the address TML of this family named
// name, "" if there is none, or the listing error.
func (sm *ShardManager) lookupTMLByName(ctx context.Context, name string) (string, error) {
	tmls, err := sm.ctrl.ListTrafficMatchingLists(ctx, sm.site)
	if err != nil {
		return "", err
	}
	want := tmlTypeForFamily(Family(sm.ipv6))
	for _, t := range tmls {
		if t.Name == name && t.Type == want {
			return t.ID, nil
		}
	}
	return "", nil
}

// lookupGroupByName returns the ID of the address group of this family named
// name, "" if there is none, or the listing error.
func (sm *ShardManager) lookupGroupByName(ctx context.Context, name string) (string, error) {
	groups, err := sm.ctrl.ListFirewallGroups(ctx, sm.site)
	if err != nil {
		return "", err
	}
	want := "address-group"
	if sm.ipv6 {
		want = "ipv6-address-group"
	}
	for _, g := range groups {
		if g.Name == name && g.GroupType == want {
			return g.ID, nil
		}
	}
	return "", nil
}

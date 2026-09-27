package firewall

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
)

// FlushDirty pushes dirty shards through the same writer used by the daemon.
func (sm *ShardManager) FlushDirty(ctx context.Context) error {
	return sm.syncAllFamilies(ctx)
}

// countDirty returns the number of shards that currently have dirty IPs.
func (sm *ShardManager) countDirty() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	n := 0
	for _, shard := range sm.fam.Shards {
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
	shards := make([]*Shard, len(sm.fam.Shards))
	copy(shards, sm.fam.Shards)
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

	// Snapshot State under the read lock to avoid races with concurrent AddIP/Rebalance
	// that read or write shard.State under sm.mu.Lock().
	sm.mu.RLock()
	state := shard.State
	groupID := shard.ID
	activationPending := shard.activationPending
	sm.mu.RUnlock()
	if !dirty {
		if activationPending {
			return sm.provisionShard(ctx, shard)
		}
		return nil
	}

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

	if sm.dryRun {
		return sm.dryRunSync(ctx, shard, len(ips), state, activationPending)
	}

	// Skip the PUT if content is unchanged from last successful flush.
	// This avoids sending large JSON payloads when the janitor marks a shard dirty
	// but no IPs actually changed (e.g., TTL-only expiry with no removal).
	// Only applicable to Active shards — Pending shards must always be flushed.
	if state == ShardStateActive && shard.IPs.SkipUnchanged() {
		sm.log.Debug().Str("shard", shard.Name).Msg("shard skipped: no change from last flush")
		return nil
	}

	// Pending→Active transition: POST to create the group first
	wasCreating := state == ShardStatePending
	if wasCreating && groupID == "" {
		if created, err := sm.createPendingShard(ctx, shard, len(ips)); !created {
			return err
		}
	}

	sort.Strings(ips)
	sentMembers, sentCount, putErr := sm.putAcceptedMembers(ctx, shard, ips)
	if putErr != nil {
		return sm.handleSyncFailure(ctx, shard, putErr, sentCount, shardLabel, start)
	}

	sm.commitSyncedMembers(shard, sentMembers, shardLabel)

	if wasCreating {
		sm.markCreatedActive(shard)
	}
	if wasCreating || activationPending {
		if err := sm.provisionShard(ctx, shard); err != nil {
			return err
		}
	}

	sm.recordSyncSuccess(shard, shardLabel, start, sentCount, len(sentMembers))
	return nil
}

// dryRunSync logs the sync that would happen, marks the shard clean, and
// treats a Pending shard as Active so its provisioning path runs.
func (sm *ShardManager) dryRunSync(ctx context.Context, shard *Shard, memberCount int,
	state ShardState, activationPending bool) error {
	sm.log.Info().Str("shard", shard.Name).Int("member_count", memberCount).
		Msgf("[DRY-RUN] would sync %s", sm.shardObjectKind())
	shard.IPs.MarkClean()
	// In dry-run, transition Pending to Active for consistency.
	if state == ShardStatePending {
		sm.mu.Lock()
		shard.State = ShardStateActive
		shard.activationPending = true
		sm.mu.Unlock()
	}
	if state == ShardStatePending || activationPending {
		return sm.provisionShard(ctx, shard)
	}
	return nil
}

// putShardMembers replaces the members of the shard's controller object with
// ips and returns the number of items sent.
func (sm *ShardManager) putShardMembers(ctx context.Context, shard *Shard, ips []string) (int, error) {
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

	if sm.mode == "zone" {
		items := make([]controller.TrafficMatchingListItem, 0, len(ips))
		for _, ip := range ips {
			items = append(items, controller.TrafficMatchingListItem{Type: addressItemType(ip), Value: ip})
		}
		return len(ips), sm.ctrl.UpdateTrafficMatchingList(ctx, sm.site, controller.TrafficMatchingList{
			ID:        shard.ID,
			Name:      shard.Name,
			Type:      tmlTypeForFamily(shard.Family),
			GroupType: groupType,
			Items:     items,
		})
	}
	return len(ips), sm.ctrl.UpdateFirewallGroup(ctx, sm.site, controller.FirewallGroup{
		ID:           shard.ID,
		Name:         shard.Name,
		GroupType:    groupType,
		GroupMembers: ips,
	})
}

// handleSyncFailure records a failed member write and signals the manager.
// It returns nil when a missing controller object was recovered.
func (sm *ShardManager) handleSyncFailure(ctx context.Context, shard *Shard, putErr error,
	ipCount int, shardLabel string, start time.Time) error {
	metrics.ShardSyncTotal.WithLabelValues(shard.Family, shardLabel, sm.site, "error").Inc()
	metrics.ShardSyncDuration.WithLabelValues(shard.Family, shardLabel, sm.site).Observe(time.Since(start).Seconds())

	// Propagate rate-limit signal to manager before logging so the manager can
	// suppress further flushes during the Retry-After window.
	var rl *controller.ErrRateLimit
	if errors.As(putErr, &rl) && sm.onRateLimit != nil {
		sm.onRateLimit(rl.RetryAfter)
		sm.log.Warn().Stringer("retry_after", rl.RetryAfter).Str("shard", shard.Name).
			Msg("rate limited by controller; backing off")
		return putErr
	}

	var nf *controller.ErrNotFound
	if errors.As(putErr, &nf) {
		if handled := sm.handleShardNotFound(ctx, shard); handled {
			return nil
		}
	}

	sm.log.Error().Err(putErr).Str("shard", shard.Name).Str("shard_id", shard.ID).Int("ip_count", ipCount).
		Msg("shard sync failed, will retry next tick")
	// A 400 means the controller answered and refused this shard's content.
	// That is not a sign of an unhealthy controller, so it must not open the
	// breaker and stall every other shard.
	var bad *controller.ErrBadRequest
	if errors.As(putErr, &bad) {
		return putErr
	}
	if sm.onSyncError != nil {
		sm.onSyncError()
	}
	return putErr
}

// markCreatedActive completes the Pending→Active transition of a newly
// created shard, keeping provisioning pending until every policy or rule exists.
func (sm *ShardManager) markCreatedActive(shard *Shard) {
	sm.mu.Lock()
	shard.State = ShardStateActive
	shard.activationPending = true
	sm.updateMetricsLocked()
	sm.mu.Unlock()
}

// commitSyncedMembers records sentMembers as the shard's flushed content and
// caches them in bbolt.
func (sm *ShardManager) commitSyncedMembers(shard *Shard, sentMembers []string, shardLabel string) {
	shard.IPs.CommitFlushed(sentMembers)
	metrics.ShardIPCount.WithLabelValues(shard.Family, shardLabel, sm.site).Set(float64(len(sentMembers)))
	if err := sm.store.SetGroup(cacheKey(sm.site, shard.Name), storage.GroupRecord{
		UnifiID: shard.ID,
		Site:    sm.site,
		Index:   shard.Index,
		Members: sentMembers,
		IPv6:    sm.ipv6,
	}); err != nil {
		sm.log.Warn().Err(err).Str("shard", shard.Name).Msg("failed to update bbolt group cache after sync")
	}
}

// recordSyncSuccess signals the manager and records metrics and logs for a
// completed shard sync.
func (sm *ShardManager) recordSyncSuccess(shard *Shard, shardLabel string, start time.Time, sentCount, realIPCount int) {
	if sm.onSyncSuccess != nil {
		sm.onSyncSuccess()
	}
	metrics.ShardSyncTotal.WithLabelValues(shard.Family, shardLabel, sm.site, "ok").Inc()
	metrics.ShardSyncDuration.WithLabelValues(shard.Family, shardLabel, sm.site).Observe(time.Since(start).Seconds())
	sm.log.Debug().Str("shard", shard.Name).Int("count", sentCount).Msg("shard synced")
	if realIPCount > 0 {
		sm.log.Info().
			Str("shard", shard.Name).
			Int("ip_count", realIPCount).
			Str("site", sm.site).
			Msg("shard flushed to UniFi")
	}
}

func (sm *ShardManager) provisionShard(ctx context.Context, shard *Shard) error {
	if sm.onActivated != nil {
		sm.mu.RLock()
		groupID := shard.ID
		sm.mu.RUnlock()
		if err := sm.onActivated(ctx, shard.Index, groupID); err != nil {
			return fmt.Errorf("provision shard %s: %w", shard.Name, err)
		}
	}
	sm.mu.Lock()
	shard.activationPending = false
	sm.updateMetricsLocked()
	sm.mu.Unlock()
	return nil
}

// MarkUnprovisioned flags an active shard whose block policy or rule could not
// be ensured. The next sync retries it, and until then its bans count as
// unsynced rather than enforced.
func (sm *ShardManager) MarkUnprovisioned(shardIdx int) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	shard := sm.findShardByIndexLocked(sm.fam, shardIdx)
	if shard == nil || shard.State != ShardStateActive {
		return
	}
	shard.activationPending = true
	sm.updateMetricsLocked()
}

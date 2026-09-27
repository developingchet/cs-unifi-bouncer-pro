package firewall

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
)

// PrunableTail returns an empty Active tail shard for removal. The conventional
// index-0 anchor is retained when it is the only shard.
func (sm *ShardManager) PrunableTail() (unifiID string, shardIdx int, ok bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	family := sm.fam

	if len(family.Shards) == 0 {
		return "", -1, false
	}

	last := family.Shards[len(family.Shards)-1]
	if len(family.Shards) == 1 && last.Index == 0 {
		return "", -1, false // retain the conventional anchor shard
	}
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
	family := sm.fam
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
	return sm.store.DeleteGroup(cacheKey(sm.site, name))
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

	family := sm.fam
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
func (sm *ShardManager) drainDraining(ctx context.Context) error {
	sm.mu.RLock()
	var draining []*Shard
	for _, s := range sm.fam.Shards {
		if s.State == ShardStateDraining {
			draining = append(draining, s)
		}
	}
	sm.mu.RUnlock()

	var drainErrors []error
	for _, shard := range draining {
		if err := sm.drainShard(ctx, shard); err != nil {
			drainErrors = append(drainErrors, err)
		}
	}
	return errors.Join(drainErrors...)
}

// drainShard deletes a single Draining shard from UniFi and removes it from memory.
// On API error the shard remains Draining and will be retried on the next tick.
func (sm *ShardManager) drainShard(ctx context.Context, shard *Shard) error {
	sm.log.Debug().
		Str("shard", shard.Name).
		Str("shard_id", shard.ID).
		Bool("onDrainedFired", shard.onDrainedFired).
		Msg("drainShard: attempt")

	// 1. Delete policies/rules first — UniFi rejects group deletion while referenced.
	// Gate on onDrainedFired so that if DeleteShardObject fails and this shard is
	// retried on the next tick, we do not attempt a duplicate policy/rule deletion.
	if sm.onDrained != nil && !shard.onDrainedFired {
		if err := sm.onDrained(ctx, shard.Index, shard.ID); err != nil {
			sm.log.Error().Err(err).Str("shard", shard.Name).
				Msg("drainShard: failed to delete referencing policies; will retry")
			return fmt.Errorf("delete references for draining shard %s: %w", shard.Name, err)
		}
		shard.onDrainedFired = true
	}

	// 2. Pace API calls with the configured shard delay.
	if sm.flushDelay > 0 {
		select {
		case <-time.After(sm.flushDelay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	// 3. Delete the UniFi TML / firewall group object.
	if shard.ID != "" {
		if err := sm.DeleteShardObject(ctx, shard.ID); err != nil {
			sm.log.Error().Err(err).
				Str("shard", shard.Name).Str("shard_id", shard.ID).
				Msg("drainShard: failed to delete UniFi object; will retry on next tick")
			return fmt.Errorf("delete draining shard %s: %w", shard.Name, err) // leave in Draining state for retry
		}
	}

	// 4. Remove from bbolt.
	if err := sm.store.DeleteGroup(cacheKey(sm.site, shard.Name)); err != nil {
		sm.log.Warn().Err(err).Str("shard", shard.Name).
			Msg("drainShard: failed to delete from bbolt")
	}

	// 5. Splice the shard out of the in-memory slice (verify state under lock).
	sm.mu.Lock()
	family := sm.fam
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
	return nil
}

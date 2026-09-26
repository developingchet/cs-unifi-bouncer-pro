package firewall

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
)

// circuitBreakerState is the state of the circuit breaker.
type circuitBreakerState int32

const (
	circuitClosed   circuitBreakerState = iota // normal: requests allowed
	circuitOpen                                // tripped: requests blocked
	circuitHalfOpen                            // probing: one request allowed
)

// circuitBreaker is a minimal three-state circuit breaker embedded in managerImpl.
// It opens after N consecutive failures and resets to half-open after a timeout.
type circuitBreaker struct {
	mu         sync.Mutex
	state      circuitBreakerState
	failures   int
	threshold  int
	resetAfter time.Duration
	openedAt   time.Time
}

func newCircuitBreaker(threshold int, resetAfter time.Duration) *circuitBreaker {
	if threshold < 1 {
		threshold = 5
	}
	if resetAfter <= 0 {
		resetAfter = 60 * time.Second
	}
	return &circuitBreaker{threshold: threshold, resetAfter: resetAfter}
}

// allow returns true if the request should be allowed through.
func (cb *circuitBreaker) allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	switch cb.state {
	case circuitClosed:
		return true
	case circuitOpen:
		if time.Since(cb.openedAt) >= cb.resetAfter {
			cb.state = circuitHalfOpen
			return true
		}
		return false
	default: // circuitHalfOpen — probe already in progress, block concurrent callers
		return false
	}
}

// recordSuccess resets the breaker to closed state.
// Returns true if the breaker was previously open or half-open (i.e. just recovered).
func (cb *circuitBreaker) recordSuccess() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	wasOpen := cb.state != circuitClosed
	cb.state = circuitClosed
	cb.failures = 0
	return wasOpen
}

// recordFailure increments the failure counter and opens the breaker when the threshold is crossed.
// Returns true if the breaker just opened.
func (cb *circuitBreaker) recordFailure() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures++
	if cb.state != circuitOpen && cb.failures >= cb.threshold {
		cb.state = circuitOpen
		cb.openedAt = time.Now()
		return true
	}
	return false
}

func (cb *circuitBreaker) isHalfOpen() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.state == circuitHalfOpen
}

// setRateLimitUntil records when the rate-limit window expires.
func (m *managerImpl) setRateLimitUntil(t time.Time) {
	m.rateLimitUntil.Store(t)
}

// isRateLimited returns true if we are still inside a rate-limit window.
func (m *managerImpl) isRateLimited() (bool, time.Time) {
	v := m.rateLimitUntil.Load()
	if v == nil {
		return false, time.Time{}
	}
	t := v.(time.Time)
	return time.Now().Before(t), t
}

// attachShardCallbacks wires rate-limit and circuit-breaker callbacks onto mgr.
// Called for both v4 and v6 ShardManagers to avoid duplicating the callback logic.
func (m *managerImpl) attachShardCallbacks(mgr *ShardManager) {
	mgr.SetRateLimitCallback(func(retryAfter time.Duration) {
		m.setRateLimitUntil(time.Now().Add(retryAfter))
	})
	mgr.SetSyncCallbacks(
		func() { // onSyncSuccess
			m.recordControllerSuccess()
		},
		func() { // onSyncError
			if tripped := m.cb.recordFailure(); tripped {
				m.log.Error().Msg("circuit breaker opened: too many consecutive sync failures")
				metrics.CircuitBreakerState.Set(1)
				if m.cfg.OnCircuitBreakerOpen != nil {
					m.cfg.OnCircuitBreakerOpen()
				}
			}
		},
	)
}

func (m *managerImpl) recordControllerSuccess() {
	if m.cb.recordSuccess() {
		m.log.Info().Msg("circuit breaker closed: controller reachable again")
		metrics.CircuitBreakerState.Set(0)
		if m.cfg.OnCircuitBreakerClose != nil {
			m.cfg.OnCircuitBreakerClose()
		}
	}
}

// SyncDirty flushes all dirty shards to the UniFi API for the given sites.
// Errors are logged per-shard and those shards remain dirty for retry on the next call.
// Updates the DirtyShards gauge with the pre-sync dirty count before flushing.
// If the controller previously signalled rate-limiting, SyncDirty skips all flushes
// until the Retry-After window has elapsed.
func (m *managerImpl) SyncDirty(ctx context.Context, sites []string) error {
	if m.cfg.DryRun {
		m.log.Debug().Msg("[DRY-RUN] skipping shard sync")
		return nil
	}
	// Check rate-limit window before doing any work.
	if limited, until := m.isRateLimited(); limited {
		m.log.Info().Time("retry_after", until).Msg("SyncDirty skipped: rate-limited by controller")
		return fmt.Errorf("sync deferred by controller rate limit until %s", until.Format(time.RFC3339))
	}

	// Check circuit breaker.
	if !m.cb.allow() {
		m.log.Info().Msg("SyncDirty skipped: circuit breaker open")
		return fmt.Errorf("sync deferred: controller circuit breaker open")
	}

	// First pass: snapshot dirty-shard counts per site so the Prometheus gauge
	// reflects pre-sync state and we know whether to emit a per-site Info log.
	siteDirty := make(map[string]int, len(sites))
	var totalDirty int
	var syncErrors []error
	deferred := false
	for _, site := range sites {
		m.mu.RLock()
		v4 := m.v4Mgrs[site]
		v6 := m.v6Mgrs[site]
		m.mu.RUnlock()

		n := 0
		if v4 != nil {
			n += v4.countDirty()
		}
		if v6 != nil {
			n += v6.countDirty()
		}
		siteDirty[site] = n
		totalDirty += n
	}
	metrics.DirtyShards.Set(float64(totalDirty))

	// dirtyFamily pairs a family's ShardManager with its name (for log fields
	// and error messages) and a pointer to that family's synced flag.
	type dirtyFamily struct {
		name   string
		sm     *ShardManager
		synced *bool
	}

	// Second pass: flush and emit a per-site Info summary when work was done.
	for _, site := range sites {
		m.mu.RLock()
		v4 := m.v4Mgrs[site]
		v6 := m.v6Mgrs[site]
		m.mu.RUnlock()

		// Rebalance, flush, and drain must be one serialized operation. A
		// concurrent reconcile must not see a Draining donor before its target
		// has been written successfully.
		if !m.syncMu.TryLock() {
			// Reconcile flushes dirty shards itself, and anything it misses is
			// flushed on the next tick, so this is routine rather than an error.
			m.log.Debug().Str("site", site).Msg("SyncDirty: deferring site flush while reconcile runs")
			deferred = true
			continue
		}
		v4Synced, v6Synced := true, true
		var families []dirtyFamily
		if v4 != nil {
			families = append(families, dirtyFamily{"v4", v4, &v4Synced})
		}
		if v6 != nil {
			families = append(families, dirtyFamily{"v6", v6, &v6Synced})
		}
		func() {
			defer m.syncMu.Unlock()
			for _, f := range families {
				if n := f.sm.Rebalance(ctx); n > 0 {
					m.log.Info().Str("site", site).Int("merged", n).Str("family", f.name).Msg("shard rebalance complete")
				}
			}
			for _, f := range families {
				if err := f.sm.syncAllFamilies(ctx); err != nil {
					*f.synced = false
					syncErrors = append(syncErrors, fmt.Errorf("sync %s shards for site %s: %w", f.name, site, err))
				}
			}
			// Drain only after each family's target shards reached the API.
			for _, f := range families {
				if !*f.synced {
					continue
				}
				if err := f.sm.drainDraining(ctx); err != nil {
					syncErrors = append(syncErrors, fmt.Errorf("drain %s shards for site %s: %w", f.name, site, err))
				}
			}
		}()

		if siteDirty[site] > 0 && v4Synced && v6Synced {
			v4Total := 0
			v6Total := 0
			if v4 != nil {
				v4Total = len(v4.AllMembers())
			}
			if v6 != nil {
				v6Total = len(v6.AllMembers())
			}
			m.log.Info().
				Str("site", site).
				Int("v4_total", v4Total).
				Int("v6_total", v6Total).
				Int("dirty_shards_flushed", siteDirty[site]).
				Msg("firewall sync complete")
		}
	}

	// Update active_bans gauge from bbolt after every sync tick.
	m.UpdateActiveBansMetric()
	if len(syncErrors) == 0 && m.cb.isHalfOpen() {
		// No shard write was available to probe the controller. A successful
		// read closes the breaker so the next decision can be flushed.
		if err := m.ctrl.Ping(ctx); err != nil {
			m.cb.recordFailure()
			syncErrors = append(syncErrors, fmt.Errorf("controller circuit breaker probe: %w", err))
		} else {
			m.recordControllerSuccess()
		}
	}
	if len(syncErrors) == 0 && !deferred {
		metrics.LastSyncTimestamp.Set(float64(time.Now().Unix()))
	}
	return errors.Join(syncErrors...)
}

// pruneEmptyTailShards deletes empty trailing shards (group + rule/policy) for both families.
func (m *managerImpl) pruneEmptyTailShards(ctx context.Context, site string, v4, v6 *ShardManager) {
	if m.cfg.DryRun {
		return
	}

	mode := m.cachedMode(site)

	type entry struct {
		sm   *ShardManager
		ipv6 bool
	}

	for _, e := range []entry{{v4, false}, {v6, true}} {
		if e.sm == nil {
			continue
		}
	pruneLoop:
		for {
			unifiID, shardIdx, ok := e.sm.PrunableTail()
			if !ok {
				break
			}

			// Delete rule/policy first (must succeed before deleting the group).
			// UniFi will reject group deletion if policies/rules still reference it.
			switch mode {
			case "legacy":
				if err := m.legacyMgr.DeleteRuleForShard(ctx, site, e.ipv6, shardIdx); err != nil {
					m.log.Error().Err(err).Str("site", site).Bool("ipv6", e.ipv6).Int("shard", shardIdx).
						Msg("failed to delete rule for pruned shard; aborting group delete to avoid orphans")
					break pruneLoop // stop pruning on error to avoid orphaning the group
				}
			case "zone":
				if err := m.zoneMgr.DeletePoliciesForShard(ctx, site, e.ipv6, shardIdx); err != nil {
					m.log.Error().Err(err).Str("site", site).Bool("ipv6", e.ipv6).Int("shard", shardIdx).
						Msg("failed to delete policies for pruned shard; aborting group delete to avoid orphans")
					break pruneLoop // stop pruning on error to avoid orphaning the group
				}
			}

			// Apply delay before group delete
			if m.cfg.APIShardDelay > 0 {
				select {
				case <-time.After(m.cfg.APIShardDelay):
				case <-ctx.Done():
					return
				}
			}

			// Delete backing shard object from UniFi.
			if err := e.sm.DeleteShardObject(ctx, unifiID); err != nil {
				m.log.Error().Err(err).Str("site", site).Bool("ipv6", e.ipv6).Int("shard", shardIdx).
					Msg("failed to delete pruned shard object")
				break // stop pruning on error to avoid inconsistency
			}

			// Finalize: remove from in-memory + bbolt
			if err := e.sm.RemoveTail(); err != nil {
				m.log.Warn().Err(err).Msg("RemoveTail bbolt error")
			}

			m.log.Info().Str("site", site).Bool("ipv6", e.ipv6).Int("shard", shardIdx).
				Msg("pruned empty shard and its firewall rule/policy")
		}
	}
}

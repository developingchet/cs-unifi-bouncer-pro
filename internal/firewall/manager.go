package firewall

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/rs/zerolog"
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

// ReconcileResult summarizes a full reconcile operation.
type ReconcileResult struct {
	Added   int
	Removed int
	Errors  []error
	Elapsed time.Duration
}

// Manager is the firewall management interface.
type Manager interface {
	// Reconcile performs a full diff between bbolt state and UniFi API state,
	// adding missing IPs and removing extra ones.
	Reconcile(ctx context.Context, sites []string) (*ReconcileResult, error)

	// ApplyBan adds an IP to the appropriate shard for all given sites.
	ApplyBan(ctx context.Context, site, ip string, ipv6 bool) error

	// ApplyBanWithZones rejects scenario-specific pairs until separate firewall
	// policies can be provisioned. Empty zonePairs uses ApplyBan.
	ApplyBanWithZones(ctx context.Context, site, ip string, ipv6 bool, zonePairs []config.ZonePair) error

	// ApplyUnban removes an IP from its shard for all given sites.
	ApplyUnban(ctx context.Context, site, ip string, ipv6 bool) error

	// EnsureInfrastructure bootstraps all firewall groups, rules, and policies
	// for every configured site. Must be called before ApplyBan/ApplyUnban.
	EnsureInfrastructure(ctx context.Context, sites []string) error

	// PrepareDrain loads current managed objects without creating or changing
	// firewall objects. Drain uses this snapshot for deletion or preview.
	PrepareDrain(ctx context.Context, sites []string) error

	// SyncDirty flushes all dirty shards to the UniFi API.
	SyncDirty(ctx context.Context, sites []string) error

	// Drain removes all managed firewall objects (policies/rules, shard groups)
	// for the given sites and cleans up bbolt state. In dry-run mode it only logs.
	Drain(ctx context.Context, sites []string) error

	// ZoneManager returns the underlying ZoneManager, or nil in legacy mode.
	ZoneManager() *ZoneManager
}

// ManagerConfig holds all firewall manager configuration.
type ManagerConfig struct {
	FirewallMode     string // "auto", "legacy", "zone"
	EnableIPv6       bool
	GroupCapacityV4  int
	GroupCapacityV6  int
	DryRun           bool
	APIShardDelay    time.Duration
	FlushConcurrency int
	LegacyCfg        LegacyConfig
	ZoneCfg          ZoneConfig

	// Circuit breaker settings. Zero values use defaults (5 failures, 60s reset).
	CircuitBreakerThreshold     int
	CircuitBreakerResetInterval time.Duration

	// ShardMergeThreshold is the IP count at or below which a shard is eligible
	// for consolidation into a larger shard (read from SHARD_MERGE_THRESHOLD).
	// 0 = auto (50% of shard capacity). -1 = disable.
	ShardMergeThreshold int

	// Optional callbacks fired when the circuit breaker changes state.
	// Nil = no-op. These are called from attachShardCallbacks.
	OnCircuitBreakerOpen  func()
	OnCircuitBreakerClose func()
}

type managerImpl struct {
	cfg   ManagerConfig
	ctrl  controller.Controller
	store storage.Store
	namer *Namer
	log   zerolog.Logger
	sites []string

	// Per-site shard managers
	mu     sync.RWMutex
	v4Mgrs map[string]*ShardManager // site -> ShardManager
	v6Mgrs map[string]*ShardManager // site -> ShardManager (nil if IPv6 disabled)

	// Mode managers
	legacyMgr *LegacyManager
	zoneMgr   *ZoneManager

	// Shared semaphore for concurrent flush limiting
	flushSem chan struct{}

	// Cached resolved mode per site (avoids repeated HasFeature API calls)
	siteMode map[string]string
	siteMu   sync.RWMutex

	// rateLimitUntil stores a time.Time; when set, SyncDirty skips all flushes
	// until the deadline passes. Set when a shard sync returns ErrRateLimit.
	rateLimitUntil atomic.Value

	// cb is the circuit breaker that opens after consecutive sync failures.
	cb *circuitBreaker

	// syncMu prevents concurrent SyncDirty executions (e.g. startup batch
	// overlapping the first ticker fire). TryLock is used so a slow flush
	// does not block the ticker goroutine — the tick is simply skipped.
	syncMu sync.Mutex

	// bgCtx is the long-lived daemon context captured on first EnsureInfrastructure
	// call. Activation callbacks use this instead of the transient ctx they receive,
	// so a cancelled startup context never breaks mid-run shard provisioning.
	bgCtx   context.Context
	bgCtxMu sync.Once
}

// NewManager constructs a Manager.
func NewManager(cfg ManagerConfig, ctrl controller.Controller, store storage.Store, namer *Namer, log zerolog.Logger) Manager {
	conc := cfg.FlushConcurrency
	if conc < 1 {
		conc = 1
	}

	legacyMgr := NewLegacyManager(cfg.LegacyCfg, namer, ctrl, store, log)
	zoneMgr := NewZoneManager(cfg.ZoneCfg, namer, ctrl, store, log)

	return &managerImpl{
		cfg:       cfg,
		ctrl:      ctrl,
		store:     store,
		namer:     namer,
		log:       log,
		v4Mgrs:    make(map[string]*ShardManager),
		v6Mgrs:    make(map[string]*ShardManager),
		legacyMgr: legacyMgr,
		zoneMgr:   zoneMgr,
		flushSem:  make(chan struct{}, conc),
		siteMode:  make(map[string]string),
		cb:        newCircuitBreaker(cfg.CircuitBreakerThreshold, cfg.CircuitBreakerResetInterval),
	}
}

// EnsureInfrastructure bootstraps all groups and rules/policies for every site.
func (m *managerImpl) EnsureInfrastructure(ctx context.Context, sites []string) error {
	m.bgCtxMu.Do(func() { m.bgCtx = ctx })
	m.sites = sites

	for _, site := range sites {
		// Callers (main.go runDaemon and reconcileCmd) pre-resolve capacities
		// via resolveCapacities() before constructing ManagerConfig.
		v4Cap := m.cfg.GroupCapacityV4
		v6Cap := m.cfg.GroupCapacityV6

		// Determine effective mode first so shard backend uses the right API object type.
		mode, err := m.resolveMode(ctx, site)
		if err != nil {
			return fmt.Errorf("resolve mode for site %s: %w", site, err)
		}

		// Cache resolved mode for use in ensureNewShardInfrastructure and pruneEmptyTailShards.
		m.siteMu.Lock()
		m.siteMode[site] = mode
		m.siteMu.Unlock()

		v4 := NewShardManager(site, false, v4Cap, m.namer, m.ctrl, m.store, m.log,
			m.cfg.APIShardDelay, m.flushSem, m.cfg.DryRun, mode)
		if err := v4.EnsureShards(ctx); err != nil {
			return fmt.Errorf("ensure v4 shards for site %s: %w", site, err)
		}

		// Clean up placeholder-only (orphaned) groups found in UniFi
		for _, orphan := range v4.TakeOrphanedGroups() {
			if m.cfg.DryRun {
				m.log.Info().Str("site", site).Str("group_name", orphan.Name).Msg("[DRY-RUN] would delete orphaned group")
				continue
			}
			m.log.Info().Str("site", site).Str("group_name", orphan.Name).Str("group_id", orphan.UnifiID).
				Msg("deleting orphaned placeholder-only group")
			// Best-effort cleanup of any policies/rules that reference this group.
			// This handles migration from pre-lazy-creation code where rules were created eagerly.
			m.deleteOrphanedReferencingObjects(ctx, site, mode, orphan.UnifiID)
			// Orphaned groups were never adopted into our memory management, so they have no policies/rules created by us.
			// Delete the group object.
			if err := v4.DeleteShardObject(ctx, orphan.UnifiID); err != nil {
				m.log.Warn().Err(err).Str("group_id", orphan.UnifiID).Msg("failed to delete orphaned group (will continue)")
			}
		}

		m.mu.Lock()
		m.v4Mgrs[site] = v4
		m.mu.Unlock()

		if m.cfg.EnableIPv6 {
			v6 := NewShardManager(site, true, v6Cap, m.namer, m.ctrl, m.store, m.log,
				m.cfg.APIShardDelay, m.flushSem, m.cfg.DryRun, mode)
			if err := v6.EnsureShards(ctx); err != nil {
				return fmt.Errorf("ensure v6 shards for site %s: %w", site, err)
			}

			// Clean up placeholder-only (orphaned) groups found in UniFi
			for _, orphan := range v6.TakeOrphanedGroups() {
				if m.cfg.DryRun {
					m.log.Info().Str("site", site).Str("group_name", orphan.Name).Msg("[DRY-RUN] would delete orphaned group")
					continue
				}
				m.log.Info().Str("site", site).Str("group_name", orphan.Name).Str("group_id", orphan.UnifiID).
					Msg("deleting orphaned placeholder-only group")
				// Best-effort cleanup of any policies/rules that reference this group.
				// This handles migration from pre-lazy-creation code where rules were created eagerly.
				m.deleteOrphanedReferencingObjects(ctx, site, mode, orphan.UnifiID)
				// Orphaned groups were never adopted into our memory management, so they have no policies/rules created by us.
				// Delete the group object.
				if err := v6.DeleteShardObject(ctx, orphan.UnifiID); err != nil {
					m.log.Warn().Err(err).Str("group_id", orphan.UnifiID).Msg("failed to delete orphaned group (will continue)")
				}
			}
			m.mu.Lock()
			m.v6Mgrs[site] = v6
			m.mu.Unlock()
		}

		m.mu.RLock()
		v4Mgr := m.v4Mgrs[site]
		v6Mgr := m.v6Mgrs[site]
		// Set activation callbacks to provision infrastructure when Pending shards become Active.
		// Use m.bgCtx (the long-lived daemon context) rather than the callback's ctx so that
		// a cancelled startup context does not abort mid-run shard provisioning.
		v4Mgr.SetActivationCallback(func(_ context.Context, shardIdx int, groupID string) error {
			if err := m.ensureNewShardInfrastructure(m.bgCtx, site, false, shardIdx, v4Mgr); err != nil {
				m.log.Error().Err(err).Str("site", site).Int("shard_idx", shardIdx).Str("group_id", groupID).
					Msg("failed to provision infrastructure for newly activated v4 shard")
				return err
			}
			return nil
		})
		m.attachShardCallbacks(v4Mgr)
		v4Mgr.SetMergeThreshold(m.cfg.ShardMergeThreshold)
		onDrained := func(ctx context.Context, shardIdx int, groupID string) error {
			mode := m.cachedMode(site)
			switch mode {
			case "legacy":
				if err := m.legacyMgr.DeleteRuleForShard(ctx, site, false, shardIdx); err != nil {
					return fmt.Errorf("delete rule for drained v4 shard %d: %w", shardIdx, err)
				}
			case "zone":
				if err := m.zoneMgr.DeletePoliciesForShard(ctx, site, false, shardIdx); err != nil {
					return fmt.Errorf("delete policies for drained v4 shard %d: %w", shardIdx, err)
				}
			}
			return nil
		}
		v4Mgr.SetDrainCallback(onDrained)
		if m.cfg.EnableIPv6 && v6Mgr != nil {
			v6Mgr.SetActivationCallback(func(_ context.Context, shardIdx int, groupID string) error {
				if err := m.ensureNewShardInfrastructure(m.bgCtx, site, true, shardIdx, v6Mgr); err != nil {
					m.log.Error().Err(err).Str("site", site).Int("shard_idx", shardIdx).Str("group_id", groupID).
						Msg("failed to provision infrastructure for newly activated v6 shard")
					return err
				}
				return nil
			})
			m.attachShardCallbacks(v6Mgr)
			v6Mgr.SetMergeThreshold(m.cfg.ShardMergeThreshold)
			onDrainedV6 := func(ctx context.Context, shardIdx int, groupID string) error {
				mode := m.cachedMode(site)
				switch mode {
				case "legacy":
					if err := m.legacyMgr.DeleteRuleForShard(ctx, site, true, shardIdx); err != nil {
						return fmt.Errorf("delete rule for drained v6 shard %d: %w", shardIdx, err)
					}
				case "zone":
					if err := m.zoneMgr.DeletePoliciesForShard(ctx, site, true, shardIdx); err != nil {
						return fmt.Errorf("delete policies for drained v6 shard %d: %w", shardIdx, err)
					}
				}
				return nil
			}
			v6Mgr.SetDrainCallback(onDrainedV6)
		}

		m.mu.RUnlock()

		switch mode {
		case "legacy":
			if m.cfg.DryRun {
				m.log.Info().Str("site", site).Str("mode", "legacy").
					Msg("[DRY-RUN] would ensure legacy firewall rules for all shards")
			} else {
				if err := m.legacyMgr.EnsureRules(ctx, site, v4Mgr, v6Mgr); err != nil {
					return fmt.Errorf("ensure legacy rules for site %s: %w", site, err)
				}
			}
		case "zone":
			if m.cfg.DryRun {
				m.log.Info().Str("site", site).Str("mode", "zone").
					Msg("[DRY-RUN] would ensure zone policies for all shards")
			} else {
				// Bootstrap performs fail-fast site UUID resolution and zone discovery.
				if err := m.zoneMgr.Bootstrap(ctx, []string{site}); err != nil {
					return fmt.Errorf("zone bootstrap for site %s: %w", site, err)
				}
				if err := m.zoneMgr.EnsurePolicies(ctx, site, v4Mgr, v6Mgr); err != nil {
					return fmt.Errorf("ensure zone policies for site %s: %w", site, err)
				}
			}
		}
	}
	return nil
}

// PrepareDrain discovers existing shards without provisioning policies or rules.
func (m *managerImpl) PrepareDrain(ctx context.Context, sites []string) error {
	for _, site := range sites {
		mode, err := m.resolveMode(ctx, site)
		if err != nil {
			return fmt.Errorf("resolve mode for site %s: %w", site, err)
		}
		v4 := NewShardManager(site, false, m.cfg.GroupCapacityV4, m.namer, m.ctrl, m.store, m.log,
			m.cfg.APIShardDelay, m.flushSem, m.cfg.DryRun, mode)
		if err := v4.EnsureShards(ctx); err != nil {
			return fmt.Errorf("load IPv4 shards for site %s: %w", site, err)
		}
		m.mu.Lock()
		m.v4Mgrs[site] = v4
		m.mu.Unlock()
		v6 := NewShardManager(site, true, m.cfg.GroupCapacityV6, m.namer, m.ctrl, m.store, m.log,
			m.cfg.APIShardDelay, m.flushSem, m.cfg.DryRun, mode)
		if err := v6.EnsureShards(ctx); err != nil {
			return fmt.Errorf("load IPv6 shards for site %s: %w", site, err)
		}
		m.mu.Lock()
		m.v6Mgrs[site] = v6
		m.mu.Unlock()
		m.siteMu.Lock()
		m.siteMode[site] = mode
		m.siteMu.Unlock()
	}
	return nil
}

// ApplyBan adds an IP to the appropriate shard and schedules a batch flush.
func (m *managerImpl) ApplyBan(ctx context.Context, site, ip string, ipv6 bool) error {
	if ipv6 && !m.cfg.EnableIPv6 {
		return nil // IPv6 firewall disabled; silently ignore IPv6 decisions
	}
	if m.cfg.DryRun {
		m.log.Info().Str("site", site).Str("ip", ip).Bool("ipv6", ipv6).Msg("[DRY-RUN] would apply ban")
		return nil
	}

	m.mu.RLock()
	sm := m.shardMgr(site, ipv6)
	m.mu.RUnlock()

	if sm == nil {
		return fmt.Errorf("no shard manager for site %s (ipv6=%v)", site, ipv6)
	}

	_, newShardIdx, err := sm.Add(ctx, ip)
	if err != nil {
		return err
	}

	if newShardIdx >= 0 {
		// New shard was allocated, but may still be Pending (not yet in UniFi).
		// Check if the shard has a valid group ID (Active), otherwise infrastructure
		// will be provisioned by the activation callback when the shard is flushed.
		if sm.GroupIDAt(newShardIdx) != "" {
			// Shard is Active: provision its firewall rule/policy immediately
			if err2 := m.ensureNewShardInfrastructure(ctx, site, ipv6, newShardIdx, sm); err2 != nil {
				m.log.Error().Err(err2).Str("site", site).Bool("ipv6", ipv6).Int("shard", newShardIdx).
					Msg("failed to provision new shard rule/policy")
			}
		}
	}

	return nil
}

// ApplyBanWithZones applies a ban only when no scenario-specific zone pairs
// are requested.
func (m *managerImpl) ApplyBanWithZones(ctx context.Context, site, ip string, ipv6 bool, zonePairs []config.ZonePair) error {
	if len(zonePairs) == 0 {
		return m.ApplyBan(ctx, site, ip, ipv6)
	}
	return fmt.Errorf("scenario zone overrides are not supported without separate firewall policies")
}

// ApplyUnban removes an IP from its shard and schedules a batch flush.
func (m *managerImpl) ApplyUnban(ctx context.Context, site, ip string, ipv6 bool) error {
	if m.cfg.DryRun {
		m.log.Info().Str("site", site).Str("ip", ip).Bool("ipv6", ipv6).Msg("[DRY-RUN] would apply unban")
		return nil
	}

	m.mu.RLock()
	sm := m.shardMgr(site, ipv6)
	m.mu.RUnlock()

	if sm == nil {
		return nil // site not managed
	}

	if _, err := sm.Remove(ctx, ip); err != nil {
		return err
	}
	return nil
}

// Reconcile performs a full diff between bbolt state and UniFi API state.
func (m *managerImpl) Reconcile(ctx context.Context, sites []string) (*ReconcileResult, error) {
	start := time.Now()
	result := &ReconcileResult{}

	for _, site := range sites {
		added, removed, errs := m.reconcileSite(ctx, site)
		result.Added += added
		result.Removed += removed
		result.Errors = append(result.Errors, errs...)

		metrics.ReconcileDelta.WithLabelValues("added", site).Set(float64(added))
		metrics.ReconcileDelta.WithLabelValues("removed", site).Set(float64(removed))
	}

	result.Elapsed = time.Since(start)
	return result, errors.Join(result.Errors...)
}

// reconcileSite diffs the bbolt ban list against all UniFi groups for one site.
func (m *managerImpl) reconcileSite(ctx context.Context, site string) (added, removed int, errs []error) {
	bans, err := m.store.BanList()
	if err != nil {
		return 0, 0, []error{fmt.Errorf("load ban list: %w", err)}
	}

	m.mu.RLock()
	v4Mgr := m.v4Mgrs[site]
	v6Mgr := m.v6Mgrs[site]
	m.mu.RUnlock()

	if v4Mgr == nil {
		return
	}

	// Build desired sets from bbolt
	desiredV4 := make(map[string]struct{})
	desiredV6 := make(map[string]struct{})
	for ip, entry := range bans {
		if entry.IPv6 {
			desiredV6[ip] = struct{}{}
		} else {
			desiredV4[ip] = struct{}{}
		}
	}

	// Add missing IPs
	for ip := range desiredV4 {
		if ctx.Err() != nil {
			return added, removed, append(errs, ctx.Err())
		}
		if !v4Mgr.Contains(ip) {
			if _, _, err := v4Mgr.Add(ctx, ip); err != nil {
				errs = append(errs, err)
			} else {
				added++
			}
		}
	}

	// Remove extra IPs from v4
	for _, ip := range v4Mgr.AllMembers() {
		if ctx.Err() != nil {
			return added, removed, append(errs, ctx.Err())
		}
		if _, ok := desiredV4[ip]; !ok {
			if _, err := v4Mgr.Remove(ctx, ip); err != nil {
				errs = append(errs, err)
			} else {
				removed++
			}
		}
	}

	// IPv6
	if v6Mgr != nil {
		for ip := range desiredV6 {
			if ctx.Err() != nil {
				return added, removed, append(errs, ctx.Err())
			}
			if !v6Mgr.Contains(ip) {
				if _, _, err := v6Mgr.Add(ctx, ip); err != nil {
					errs = append(errs, err)
				} else {
					added++
				}
			}
		}
		for _, ip := range v6Mgr.AllMembers() {
			if ctx.Err() != nil {
				return added, removed, append(errs, ctx.Err())
			}
			if _, ok := desiredV6[ip]; !ok {
				if _, err := v6Mgr.Remove(ctx, ip); err != nil {
					errs = append(errs, err)
				} else {
					removed++
				}
			}
		}
	}

	if m.cfg.DryRun {
		if added > 0 || removed > 0 {
			m.log.Info().Str("site", site).Int("would_add", added).Int("would_remove", removed).
				Msg("[DRY-RUN] reconcile diff computed; no changes written to UniFi")
		}
	} else {
		func() {
			m.syncMu.Lock()
			defer m.syncMu.Unlock()
			flushed := true
			if err := v4Mgr.syncAllFamilies(ctx); err != nil {
				errs = append(errs, fmt.Errorf("v4 flush: %w", err))
				flushed = false
			}
			if v6Mgr != nil {
				if err := v6Mgr.syncAllFamilies(ctx); err != nil {
					errs = append(errs, fmt.Errorf("v6 flush: %w", err))
					flushed = false
				}
			}
			if !flushed {
				return // preserve donor policies until their target has been flushed
			}
			if err := v4Mgr.drainDraining(ctx); err != nil {
				errs = append(errs, fmt.Errorf("drain v4 shards: %w", err))
			}
			if v6Mgr != nil {
				if err := v6Mgr.drainDraining(ctx); err != nil {
					errs = append(errs, fmt.Errorf("drain v6 shards: %w", err))
				}
			}
			m.pruneEmptyTailShards(ctx, site, v4Mgr, v6Mgr)
			// Membership alone does not enforce bans. Repair policies/rules that were
			// deleted externally or missed when an activation callback failed.
			switch m.cachedMode(site) {
			case "zone":
				if err := m.zoneMgr.EnsurePolicies(ctx, site, v4Mgr, v6Mgr); err != nil {
					errs = append(errs, fmt.Errorf("ensure zone policies for site %s: %w", site, err))
				}
			case "legacy":
				if err := m.legacyMgr.EnsureRules(ctx, site, v4Mgr, v6Mgr); err != nil {
					errs = append(errs, fmt.Errorf("ensure legacy rules for site %s: %w", site, err))
				}
			}
		}()
	}

	return
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
			m.log.Warn().Str("site", site).Msg("SyncDirty: skipping site flush — reconcile in progress")
			syncErrors = append(syncErrors, fmt.Errorf("sync site %s deferred: reconcile in progress", site))
			continue
		}
		v4Synced, v6Synced := true, true
		func() {
			defer m.syncMu.Unlock()
			if v4 != nil {
				if n := v4.Rebalance(ctx); n > 0 {
					m.log.Info().Str("site", site).Int("merged", n).Str("family", "v4").Msg("shard rebalance complete")
				}
			}
			if v6 != nil {
				if n := v6.Rebalance(ctx); n > 0 {
					m.log.Info().Str("site", site).Int("merged", n).Str("family", "v6").Msg("shard rebalance complete")
				}
			}
			if v4 != nil {
				if err := v4.syncAllFamilies(ctx); err != nil {
					v4Synced = false
					syncErrors = append(syncErrors, fmt.Errorf("sync v4 shards for site %s: %w", site, err))
				}
			}
			if v6 != nil {
				if err := v6.syncAllFamilies(ctx); err != nil {
					v6Synced = false
					syncErrors = append(syncErrors, fmt.Errorf("sync v6 shards for site %s: %w", site, err))
				}
			}
			// Drain only after each family's target shards reached the API.
			if v4 != nil && v4Synced {
				if err := v4.drainDraining(ctx); err != nil {
					syncErrors = append(syncErrors, fmt.Errorf("drain v4 shards for site %s: %w", site, err))
				}
			}
			if v6 != nil && v6Synced {
				if err := v6.drainDraining(ctx); err != nil {
					syncErrors = append(syncErrors, fmt.Errorf("drain v6 shards for site %s: %w", site, err))
				}
			}
		}()

		if siteDirty[site] > 0 {
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
	if len(syncErrors) == 0 {
		metrics.LastSyncTimestamp.Set(float64(time.Now().Unix()))
	}
	return errors.Join(syncErrors...)
}

// Drain removes all managed firewall objects for the given sites and cleans up bbolt.
// Order per site: policies/rules first, then TML groups, then bbolt cleanup.
func (m *managerImpl) Drain(ctx context.Context, sites []string) error {
	drainedPolicies := 0
	drainedShards := 0
	var drainErrors []error

	for _, site := range sites {
		policies, err := m.store.ListPolicies()
		if err != nil {
			drainErrors = append(drainErrors, fmt.Errorf("list policies for site %s: %w", site, err))
			continue
		}
		for name, rec := range policies {
			if rec.Site != site {
				continue
			}
			drainedPolicies++
			if m.cfg.DryRun {
				m.log.Info().Str("site", site).Str("policy", name).Str("policy_id", rec.UnifiID).
					Msg("[DRY-RUN] would delete firewall policy or rule")
			}
		}

		groups, err := m.store.ListGroups()
		if err != nil {
			drainErrors = append(drainErrors, fmt.Errorf("list groups for site %s: %w", site, err))
			continue
		}

		m.mu.RLock()
		v4 := m.v4Mgrs[site]
		v6 := m.v6Mgrs[site]
		m.mu.RUnlock()
		groupIDs := make(map[string]struct{})
		for _, rec := range groups {
			if rec.Site == site && rec.UnifiID != "" {
				groupIDs[rec.UnifiID] = struct{}{}
			}
		}
		for _, sm := range []*ShardManager{v4, v6} {
			if sm == nil {
				continue
			}
			for _, groupID := range sm.GroupIDs() {
				groupIDs[groupID] = struct{}{}
			}
			for _, orphan := range sm.TakeOrphanedGroups() {
				groupIDs[orphan.UnifiID] = struct{}{}
			}
		}
		if m.cfg.DryRun {
			for groupID := range groupIDs {
				m.log.Info().Str("site", site).Str("group_id", groupID).
					Msg("[DRY-RUN] would delete shard group")
				drainedShards++
			}
			continue
		}

		// Rules and policies must be gone before their groups can be deleted.
		policyErr := errors.Join(m.zoneMgr.DeletePolicies(ctx, site), m.legacyMgr.DeleteRules(ctx, site))
		if policyErr != nil {
			drainErrors = append(drainErrors, fmt.Errorf("delete policies for site %s: %w", site, policyErr))
			continue
		}
		groupFailed := false
		for groupID := range groupIDs {
			if err := m.deleteDrainGroup(ctx, site, groupID); err != nil {
				groupFailed = true
				drainErrors = append(drainErrors, fmt.Errorf("delete group %s for site %s: %w", groupID, site, err))
				continue
			}
			drainedShards++
			for name, rec := range groups {
				if rec.Site == site && rec.UnifiID == groupID {
					if err := m.store.DeleteGroup(name); err != nil {
						groupFailed = true
						drainErrors = append(drainErrors, fmt.Errorf("remove group %s from storage: %w", name, err))
					}
				}
			}
		}
		if !groupFailed {
			for name, rec := range groups {
				if rec.Site == site && rec.UnifiID == "" {
					if err := m.store.DeleteGroup(name); err != nil {
						drainErrors = append(drainErrors, fmt.Errorf("remove pending group %s from storage: %w", name, err))
					}
				}
			}
		}
	}

	m.log.Info().
		Int("policies", drainedPolicies).
		Int("shards", drainedShards).
		Bool("dry_run", m.cfg.DryRun).
		Msg("drain complete")
	return errors.Join(drainErrors...)
}

func (m *managerImpl) deleteDrainGroup(ctx context.Context, site, id string) error {
	zone := m.cachedMode(site) == "zone"
	deleteGroup := m.ctrl.DeleteFirewallGroup
	deleteOther := m.ctrl.DeleteTrafficMatchingList
	if zone {
		deleteGroup, deleteOther = deleteOther, deleteGroup
	}
	err := deleteGroup(ctx, site, id)
	if err == nil {
		return nil
	}
	var missing *controller.ErrNotFound
	if !errors.As(err, &missing) {
		return err
	}
	// The mode may have changed since this shard was created.
	err = deleteOther(ctx, site, id)
	if errors.As(err, &missing) {
		return nil
	}
	return err
}

// ZoneManager returns the underlying ZoneManager, or nil in legacy mode.
func (m *managerImpl) ZoneManager() *ZoneManager {
	return m.zoneMgr
}

// ensureNewShardInfrastructure provisions the firewall rule/policy for a newly created shard.
func (m *managerImpl) ensureNewShardInfrastructure(ctx context.Context, site string, ipv6 bool, shardIdx int, sm *ShardManager) error {
	if m.cfg.DryRun {
		m.log.Info().Str("site", site).Bool("ipv6", ipv6).Int("shard", shardIdx).
			Msg("[DRY-RUN] would provision firewall rule/policy for new shard")
		return nil
	}

	// Apply delay before the API call (the group was just created; give the UDM a moment)
	if m.cfg.APIShardDelay > 0 {
		select {
		case <-time.After(m.cfg.APIShardDelay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	// Get the new shard's UniFi group ID
	groupID := sm.GroupIDAt(shardIdx)

	// If the shard is still Pending (empty group ID), skip provisioning.
	// Infrastructure will be provisioned later by the activation callback.
	if groupID == "" {
		return fmt.Errorf("active shard %d has no UniFi group ID", shardIdx)
	}

	mode := m.cachedMode(site)
	switch mode {
	case "legacy":
		return m.legacyMgr.EnsureRuleForShard(ctx, site, groupID, ipv6, shardIdx)
	case "zone":
		return m.zoneMgr.EnsurePoliciesForShard(ctx, site, groupID, ipv6, shardIdx)
	}
	return nil
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

// deleteOrphanedReferencingObjects performs best-effort cleanup of any policies/rules that reference
// an orphaned group. This handles migration from pre-lazy-creation code where rules were created eagerly.
// Errors are logged as warnings and do not cause the overall orphan cleanup to fail.
func (m *managerImpl) deleteOrphanedReferencingObjects(ctx context.Context, site, mode, groupID string) {
	switch mode {
	case "legacy":
		rules, err := m.ctrl.ListFirewallRules(ctx, site)
		if err != nil {
			m.log.Warn().Err(err).Str("site", site).Str("group_id", groupID).
				Msg("failed to list firewall rules for orphan cleanup (skipping)")
			return
		}
		for _, rule := range rules {
			if !m.ownsOrphanReference(site, "legacy", rule.Name, rule.ID, rule.Description) ||
				(rule.Action != "drop" && rule.Action != "reject") {
				continue
			}
			// Check if this rule references the orphaned group
			for _, ruleGroupID := range rule.SrcFirewallGroupIDs {
				if ruleGroupID == groupID {
					if err := m.ctrl.DeleteFirewallRule(ctx, site, rule.ID); err != nil {
						m.log.Warn().Err(err).Str("site", site).Str("rule_id", rule.ID).Str("group_id", groupID).
							Msg("failed to delete orphaned firewall rule (will continue)")
					} else {
						m.log.Info().Str("site", site).Str("rule_id", rule.ID).Str("group_id", groupID).
							Msg("deleted firewall rule referencing orphaned group")
					}
					break
				}
			}
		}
	case "zone":
		policies, err := m.ctrl.ListZonePolicies(ctx, site)
		if err != nil {
			m.log.Warn().Err(err).Str("site", site).Str("group_id", groupID).
				Msg("failed to list zone policies for orphan cleanup (skipping)")
			return
		}
		for _, policy := range policies {
			if !m.ownsOrphanReference(site, "zone", policy.Name, policy.ID, policy.Description) || policy.Action != "BLOCK" {
				continue
			}
			// Check if this policy references the orphaned group
			for _, policyGroupID := range policy.TrafficMatchingListIDs {
				if policyGroupID == groupID {
					if err := m.ctrl.DeleteZonePolicy(ctx, site, policy.ID); err != nil {
						m.log.Warn().Err(err).Str("site", site).Str("policy_id", policy.ID).Str("group_id", groupID).
							Msg("failed to delete orphaned zone policy (will continue)")
					} else {
						m.log.Info().Str("site", site).Str("policy_id", policy.ID).Str("group_id", groupID).
							Msg("deleted zone policy referencing orphaned group")
					}
					break
				}
			}
		}
	}
}

func (m *managerImpl) ownsOrphanReference(site, mode, name, id, description string) bool {
	if rec, err := getCachedPolicy(m.store, site, name); err == nil && rec != nil && rec.UnifiID == id && rec.Site == site && rec.Mode == mode {
		return true
	}
	expectedDescription := m.cfg.ZoneCfg.Description
	prefix := m.namer.PolicyPrefix()
	if mode == "legacy" {
		expectedDescription = m.cfg.LegacyCfg.Description
		prefix = m.namer.RulePrefix()
	}
	return description == expectedDescription && prefix != "" && strings.HasPrefix(name, prefix)
}

// cachedMode returns the resolved firewall mode for a site (cached from EnsureInfrastructure).
func (m *managerImpl) cachedMode(site string) string {
	m.siteMu.RLock()
	mode := m.siteMode[site]
	m.siteMu.RUnlock()
	return mode
}

// resolveMode determines the effective firewall mode for a site.
func (m *managerImpl) resolveMode(ctx context.Context, site string) (string, error) {
	if m.cfg.FirewallMode != "auto" {
		return m.cfg.FirewallMode, nil
	}
	// Auto-detect
	hasZone, err := m.ctrl.HasFeature(ctx, site, controller.FeatureZoneBasedFirewall)
	if err != nil {
		m.log.Warn().Err(err).Str("site", site).Msg("zone feature detection failed, falling back to legacy")
		return "legacy", nil
	}
	if hasZone {
		return "zone", nil
	}
	return "legacy", nil
}

// shardMgr returns the ShardManager for a site/family (must be called with mu held).
func (m *managerImpl) shardMgr(site string, ipv6 bool) *ShardManager {
	if ipv6 {
		return m.v6Mgrs[site]
	}
	return m.v4Mgrs[site]
}

// UpdateActiveBansMetric updates the active_bans gauge from bbolt.
func (m *managerImpl) UpdateActiveBansMetric() {
	bans, err := m.store.BanList()
	if err != nil {
		m.log.Warn().Err(err).Msg("failed to load ban list for metrics")
		return
	}

	// Count per site (approximate — bans are site-independent in bbolt)
	v4Count := 0
	v6Count := 0
	for _, entry := range bans {
		if entry.IPv6 {
			v6Count++
		} else {
			v4Count++
		}
	}

	for _, site := range m.sites {
		metrics.ActiveBans.WithLabelValues("v4", site).Set(float64(v4Count))
		if m.cfg.EnableIPv6 {
			metrics.ActiveBans.WithLabelValues("v6", site).Set(float64(v6Count))
		}
	}
}

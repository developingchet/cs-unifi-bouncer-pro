package firewall

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/rs/zerolog"
)

// ReconcileResult summarizes a full reconcile operation.
type ReconcileResult struct {
	Added   int
	Removed int
	Errors  []error
	Elapsed time.Duration
}

// Manager is the firewall management interface.
type Manager interface {
	Reconcile(ctx context.Context, sites []string) (*ReconcileResult, error)
	ApplyBan(ctx context.Context, site, ip string, ipv6 bool) error
	ApplyUnban(ctx context.Context, site, ip string, ipv6 bool) error
	EnsureInfrastructure(ctx context.Context, sites []string) error
}

// ManagerConfig holds all firewall manager configuration.
type ManagerConfig struct {
	FirewallMode     string // "auto", "legacy", "zone"
	EnableIPv6       bool
	GroupCapacityV4  int
	GroupCapacityV6  int
	BatchWindow      time.Duration
	DryRun           bool
	APIShardDelay    time.Duration
	FlushConcurrency int
	LegacyCfg        LegacyConfig
	ZoneCfg          ZoneConfig
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

	// Batch flush timers per site (one per site, flushes both v4 and v6)
	batchMu     sync.Mutex
	batchTimers map[string]*time.Timer
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
		cfg:         cfg,
		ctrl:        ctrl,
		store:       store,
		namer:       namer,
		log:         log,
		v4Mgrs:      make(map[string]*ShardManager),
		v6Mgrs:      make(map[string]*ShardManager),
		legacyMgr:   legacyMgr,
		zoneMgr:     zoneMgr,
		flushSem:    make(chan struct{}, conc),
		siteMode:    make(map[string]string),
		batchTimers: make(map[string]*time.Timer),
	}
}

// EnsureInfrastructure bootstraps all groups and rules/policies for every site.
func (m *managerImpl) EnsureInfrastructure(ctx context.Context, sites []string) error {
	m.sites = sites

	for _, site := range sites {
		// Callers (main.go runDaemon and reconcileCmd) pre-resolve capacities
		// via resolveCapacities() before constructing ManagerConfig.
		v4Cap := m.cfg.GroupCapacityV4
		v6Cap := m.cfg.GroupCapacityV6

		v4 := NewShardManager(site, false, v4Cap, m.namer, m.ctrl, m.store, m.log,
			m.cfg.APIShardDelay, m.flushSem, m.cfg.DryRun)
		if err := v4.EnsureShards(ctx); err != nil {
			return fmt.Errorf("ensure v4 shards for site %s: %w", site, err)
		}

		m.mu.Lock()
		m.v4Mgrs[site] = v4
		m.mu.Unlock()

		if m.cfg.EnableIPv6 {
			v6 := NewShardManager(site, true, v6Cap, m.namer, m.ctrl, m.store, m.log,
				m.cfg.APIShardDelay, m.flushSem, m.cfg.DryRun)
			if err := v6.EnsureShards(ctx); err != nil {
				return fmt.Errorf("ensure v6 shards for site %s: %w", site, err)
			}
			m.mu.Lock()
			m.v6Mgrs[site] = v6
			m.mu.Unlock()
		}

		// Determine effective mode
		mode, err := m.resolveMode(ctx, site)
		if err != nil {
			return fmt.Errorf("resolve mode for site %s: %w", site, err)
		}

		// Cache resolved mode for use in ensureNewShardInfrastructure and pruneEmptyTailShards
		m.siteMu.Lock()
		m.siteMode[site] = mode
		m.siteMu.Unlock()

		m.mu.RLock()
		v4Mgr := m.v4Mgrs[site]
		v6Mgr := m.v6Mgrs[site]
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
				if err := m.zoneMgr.EnsurePolicies(ctx, site, v4Mgr, v6Mgr); err != nil {
					return fmt.Errorf("ensure zone policies for site %s: %w", site, err)
				}
			}
		}
	}
	return nil
}

// ApplyBan adds an IP to the appropriate shard and schedules a batch flush.
func (m *managerImpl) ApplyBan(ctx context.Context, site, ip string, ipv6 bool) error {
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

	shardName, newShardIdx, err := sm.Add(ctx, ip)
	if err != nil {
		return err
	}

	if newShardIdx >= 0 {
		// New shard was created: provision its firewall rule/policy immediately
		if err2 := m.ensureNewShardInfrastructure(ctx, site, ipv6, newShardIdx, sm); err2 != nil {
			m.log.Error().Err(err2).Str("site", site).Bool("ipv6", ipv6).Int("shard", newShardIdx).
				Msg("failed to provision new shard rule/policy")
		}
	}

	if shardName != "" {
		m.scheduleBatchFlush(ctx, site)
	}
	return nil
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
	m.scheduleBatchFlush(ctx, site)
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
	return result, nil
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
		if !v4Mgr.Contains(ip) {
			if _, newIdx, err := v4Mgr.Add(ctx, ip); err != nil {
				errs = append(errs, err)
			} else {
				added++
				if newIdx >= 0 {
					if err2 := m.ensureNewShardInfrastructure(ctx, site, false, newIdx, v4Mgr); err2 != nil {
						m.log.Error().Err(err2).Str("site", site).Int("shard", newIdx).
							Msg("failed to provision new v4 shard rule/policy during reconcile")
					}
				}
			}
		}
	}

	// Remove extra IPs from v4
	for _, ip := range v4Mgr.AllMembers() {
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
			if !v6Mgr.Contains(ip) {
				if _, newIdx, err := v6Mgr.Add(ctx, ip); err != nil {
					errs = append(errs, err)
				} else {
					added++
					if newIdx >= 0 {
						if err2 := m.ensureNewShardInfrastructure(ctx, site, true, newIdx, v6Mgr); err2 != nil {
							m.log.Error().Err(err2).Str("site", site).Int("shard", newIdx).
								Msg("failed to provision new v6 shard rule/policy during reconcile")
						}
					}
				}
			}
		}
		for _, ip := range v6Mgr.AllMembers() {
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
		if err := v4Mgr.FlushDirty(ctx); err != nil {
			errs = append(errs, err)
		}
		if v6Mgr != nil {
			if err := v6Mgr.FlushDirty(ctx); err != nil {
				errs = append(errs, err)
			}
		}
		m.pruneEmptyTailShards(ctx, site, v4Mgr, v6Mgr)
	}

	return
}

// scheduleBatchFlush resets (or starts) the batch window timer for a site.
// One timer per site handles both v4 and v6 families.
func (m *managerImpl) scheduleBatchFlush(ctx context.Context, site string) {
	m.batchMu.Lock()
	defer m.batchMu.Unlock()

	if t, ok := m.batchTimers[site]; ok {
		t.Reset(m.cfg.BatchWindow)
		return
	}

	m.batchTimers[site] = time.AfterFunc(m.cfg.BatchWindow, func() {
		m.mu.RLock()
		v4 := m.v4Mgrs[site]
		v6 := m.v6Mgrs[site]
		m.mu.RUnlock()

		if v4 != nil {
			if err := v4.FlushDirty(ctx); err != nil {
				m.log.Error().Err(err).Str("site", site).Msg("batch flush v4 failed")
			}
		}
		if v6 != nil {
			if err := v6.FlushDirty(ctx); err != nil {
				m.log.Error().Err(err).Str("site", site).Msg("batch flush v6 failed")
			}
		}

		// Prune empty tail shards after flush
		m.pruneEmptyTailShards(ctx, site, v4, v6)

		m.batchMu.Lock()
		delete(m.batchTimers, site)
		m.batchMu.Unlock()
	})
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
	ids := sm.GroupIDs()
	if shardIdx >= len(ids) {
		return fmt.Errorf("shard %d not found (have %d shards)", shardIdx, len(ids))
	}
	groupID := ids[shardIdx]

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
		for {
			unifiID, shardIdx, ok := e.sm.PrunableTail()
			if !ok {
				break
			}

			// Delete rule/policy first (best-effort; log but don't abort)
			switch mode {
			case "legacy":
				if err := m.legacyMgr.DeleteRuleForShard(ctx, site, e.ipv6, shardIdx); err != nil {
					m.log.Warn().Err(err).Str("site", site).Bool("ipv6", e.ipv6).Int("shard", shardIdx).
						Msg("failed to delete rule for pruned shard")
				}
			case "zone":
				if err := m.zoneMgr.DeletePoliciesForShard(ctx, site, e.ipv6, shardIdx); err != nil {
					m.log.Warn().Err(err).Str("site", site).Bool("ipv6", e.ipv6).Int("shard", shardIdx).
						Msg("failed to delete policies for pruned shard")
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

			// Delete group from UniFi
			if err := m.ctrl.DeleteFirewallGroup(ctx, site, unifiID); err != nil {
				m.log.Error().Err(err).Str("site", site).Bool("ipv6", e.ipv6).Int("shard", shardIdx).
					Msg("failed to delete pruned shard group")
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

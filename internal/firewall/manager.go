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
	FirewallMode    string // "auto", "legacy", "zone"
	EnableIPv6      bool
	GroupCapacityV4 int
	GroupCapacityV6 int
	BatchWindow     time.Duration
	DryRun          bool
	LegacyCfg       LegacyConfig
	ZoneCfg         ZoneConfig
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

	// Batch flush timers per site
	batchMu     sync.Mutex
	batchTimers map[string]*time.Timer
}

// NewManager constructs a Manager.
func NewManager(cfg ManagerConfig, ctrl controller.Controller, store storage.Store, namer *Namer, log zerolog.Logger) Manager {
	var legacyMgr *LegacyManager
	var zoneMgr *ZoneManager

	legacyMgr = NewLegacyManager(cfg.LegacyCfg, namer, ctrl, store, log)
	zoneMgr = NewZoneManager(cfg.ZoneCfg, namer, ctrl, store, log)

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

		v4 := NewShardManager(site, false, v4Cap, m.namer, m.ctrl, m.store, m.log)
		if err := v4.EnsureShards(ctx); err != nil {
			return fmt.Errorf("ensure v4 shards for site %s: %w", site, err)
		}

		m.mu.Lock()
		m.v4Mgrs[site] = v4
		m.mu.Unlock()

		if m.cfg.EnableIPv6 {
			v6 := NewShardManager(site, true, v6Cap, m.namer, m.ctrl, m.store, m.log)
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

		m.mu.RLock()
		v4Mgr := m.v4Mgrs[site]
		v6Mgr := m.v6Mgrs[site]
		m.mu.RUnlock()

		switch mode {
		case "legacy":
			if err := m.legacyMgr.EnsureRules(ctx, site, v4Mgr, v6Mgr); err != nil {
				return fmt.Errorf("ensure legacy rules for site %s: %w", site, err)
			}
		case "zone":
			if err := m.zoneMgr.EnsurePolicies(ctx, site, v4Mgr, v6Mgr); err != nil {
				return fmt.Errorf("ensure zone policies for site %s: %w", site, err)
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

	shardName, err := sm.Add(ctx, ip)
	if err != nil {
		return err
	}
	if shardName != "" {
		m.scheduleBatchFlush(ctx, site, ipv6)
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
	m.scheduleBatchFlush(ctx, site, ipv6)
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
			if _, err := v4Mgr.Add(ctx, ip); err != nil {
				errs = append(errs, err)
			} else {
				added++
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
				if _, err := v6Mgr.Add(ctx, ip); err != nil {
					errs = append(errs, err)
				} else {
					added++
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

	// Flush all dirty shards
	if err := v4Mgr.FlushDirty(ctx); err != nil {
		errs = append(errs, err)
	}
	if v6Mgr != nil {
		if err := v6Mgr.FlushDirty(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return
}

// scheduleBatchFlush resets (or starts) the batch window timer for a site.
func (m *managerImpl) scheduleBatchFlush(ctx context.Context, site string, ipv6 bool) {
	key := site
	if ipv6 {
		key += ":v6"
	}

	m.batchMu.Lock()
	defer m.batchMu.Unlock()

	if t, ok := m.batchTimers[key]; ok {
		t.Reset(m.cfg.BatchWindow)
		return
	}

	m.batchTimers[key] = time.AfterFunc(m.cfg.BatchWindow, func() {
		m.mu.RLock()
		sm := m.shardMgr(site, ipv6)
		m.mu.RUnlock()

		if sm == nil {
			return
		}
		if err := sm.FlushDirty(ctx); err != nil {
			m.log.Error().Err(err).Str("site", site).Bool("ipv6", ipv6).Msg("batch flush failed")
		}

		m.batchMu.Lock()
		delete(m.batchTimers, key)
		m.batchMu.Unlock()
	})
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

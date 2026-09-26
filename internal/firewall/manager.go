package firewall

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
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
	// Reconcile performs a full diff between bbolt state and UniFi API state,
	// adding missing IPs and removing extra ones.
	Reconcile(ctx context.Context, sites []string) (*ReconcileResult, error)

	// ApplyBan adds an IP to the appropriate shard for all given sites.
	ApplyBan(ctx context.Context, site, ip string, ipv6 bool) error

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
		m.cleanupOrphanedShardGroups(ctx, site, mode, v4)

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
			m.cleanupOrphanedShardGroups(ctx, site, mode, v6)
			m.mu.Lock()
			m.v6Mgrs[site] = v6
			m.mu.Unlock()
		}

		m.mu.RLock()
		v4Mgr := m.v4Mgrs[site]
		v6Mgr := m.v6Mgrs[site]
		m.wireShardManager(site, false, v4Mgr)
		if m.cfg.EnableIPv6 && v6Mgr != nil {
			m.wireShardManager(site, true, v6Mgr)
		}
		m.mu.RUnlock()

		switch mode {
		case "legacy":
			if m.cfg.DryRun {
				m.log.Info().Str("site", site).Str("mode", "legacy").
					Msg("[DRY-RUN] would ensure legacy firewall rules for all shards")
			} else {
				if err := m.tolerateShardFailures(site, m.legacyMgr.EnsureRules(ctx, site, v4Mgr, v6Mgr)); err != nil {
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
				if err := m.tolerateShardFailures(site, m.zoneMgr.EnsurePolicies(ctx, site, v4Mgr, v6Mgr)); err != nil {
					return fmt.Errorf("ensure zone policies for site %s: %w", site, err)
				}
			}
		}
	}
	return nil
}

// wireShardManager installs the activation, sync, merge and drain hooks on
// one address family's shard manager for site.
func (m *managerImpl) wireShardManager(site string, ipv6 bool, sm *ShardManager) {
	fam := Family(ipv6)
	activationFailedMsg := "failed to provision infrastructure for newly activated " + fam + " shard"
	// Provision infrastructure when Pending shards become Active. Use m.bgCtx
	// (the long-lived daemon context) rather than the callback's ctx so that
	// a cancelled startup context does not abort mid-run shard provisioning.
	sm.SetActivationCallback(func(_ context.Context, shardIdx int, groupID string) error {
		if err := m.ensureNewShardInfrastructure(m.bgCtx, site, ipv6, shardIdx, sm); err != nil {
			m.log.Error().Err(err).Str("site", site).Int("shard_idx", shardIdx).Str("group_id", groupID).
				Msg(activationFailedMsg)
			return err
		}
		return nil
	})
	m.attachShardCallbacks(sm)
	sm.SetMergeThreshold(m.cfg.ShardMergeThreshold)
	sm.SetDrainCallback(func(ctx context.Context, shardIdx int, _ string) error {
		switch m.cachedMode(site) {
		case "legacy":
			if err := m.legacyMgr.DeleteRuleForShard(ctx, site, ipv6, shardIdx); err != nil {
				return fmt.Errorf("delete rule for drained %s shard %d: %w", fam, shardIdx, err)
			}
		case "zone":
			if err := m.zoneMgr.DeletePoliciesForShard(ctx, site, ipv6, shardIdx); err != nil {
				return fmt.Errorf("delete policies for drained %s shard %d: %w", fam, shardIdx, err)
			}
		}
		return nil
	})
}

// cleanupOrphanedShardGroups deletes placeholder-only (orphaned) groups found
// in UniFi for sm, along with any policies/rules that still reference them.
// Orphaned groups were never adopted into our memory management, so they have
// no policies/rules created by us beyond this best-effort migration cleanup.
func (m *managerImpl) cleanupOrphanedShardGroups(ctx context.Context, site, mode string, sm *ShardManager) {
	for _, orphan := range sm.TakeOrphanedGroups() {
		if m.cfg.DryRun {
			m.log.Info().Str("site", site).Str("group_name", orphan.Name).Msg("[DRY-RUN] would delete orphaned group")
			continue
		}
		m.log.Info().Str("site", site).Str("group_name", orphan.Name).Str("group_id", orphan.UnifiID).
			Msg("deleting orphaned placeholder-only group")
		// Best-effort cleanup of any policies/rules that reference this group.
		// This handles migration from pre-lazy-creation code where rules were created eagerly.
		m.deleteOrphanedReferencingObjects(ctx, site, mode, orphan.UnifiID)
		// Delete the group object.
		if err := sm.DeleteShardObject(ctx, orphan.UnifiID); err != nil {
			m.log.Warn().Err(err).Str("group_id", orphan.UnifiID).Msg("failed to delete orphaned group (will continue)")
		}
	}
}

// tolerateShardFailures lets startup continue when only individual shards
// lack their block policy or rule. Those shards are retried on every sync and
// counted in unsynced_ips, which is better than refusing to start and
// enforcing nothing.
func (m *managerImpl) tolerateShardFailures(site string, err error) error {
	if err == nil || !IsShardProvisionError(err) {
		return err
	}
	m.log.Error().Err(err).Str("site", site).
		Msg("some shards have no block policy or rule; their bans are not enforced yet and are retried on every sync")
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
	// A transient detection failure must not pick legacy mode on a zone-based
	// controller: the legacy objects would be created but never enforced.
	hasZone, err := m.ctrl.HasFeature(ctx, site, controller.FeatureZoneBasedFirewall)
	if err != nil {
		return "", fmt.Errorf("detect zone-based firewall support: %w", err)
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

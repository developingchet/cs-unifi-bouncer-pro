package firewall

import (
	"context"
	"errors"
	"fmt"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
)

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

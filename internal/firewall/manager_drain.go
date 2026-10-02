package firewall

import (
	"context"
	"errors"
	"fmt"
)

// PrepareDrain discovers existing shards without provisioning policies or rules.
func (m *managerImpl) PrepareDrain(ctx context.Context, sites []string) error {
	for _, site := range sites {
		mode, err := m.resolveMode(ctx, site)
		if err != nil {
			return fmt.Errorf("resolve mode for site %s: %w", site, err)
		}
		v4 := NewShardManager(site, false, m.cfg.GroupCapacityV4, m.namer, m.ctrl, m.store, m.log,
			m.cfg.APIShardDelay, m.cfg.DryRun, mode)
		if err := v4.EnsureShards(ctx); err != nil {
			return fmt.Errorf("load IPv4 shards for site %s: %w", site, err)
		}
		m.mu.Lock()
		m.v4Mgrs[site] = v4
		m.mu.Unlock()
		v6 := NewShardManager(site, true, m.cfg.GroupCapacityV6, m.namer, m.ctrl, m.store, m.log,
			m.cfg.APIShardDelay, m.cfg.DryRun, mode)
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
			if err := m.drainZoneExtras(ctx, site); err != nil {
				drainErrors = append(drainErrors, err)
			}
			continue
		}

		// Rules and policies must be gone before their groups can be deleted.
		policyErr := errors.Join(m.zoneMgr.DeletePolicies(ctx, site), m.legacyMgr.DeleteRules(ctx, site))
		if policyErr != nil {
			drainErrors = append(drainErrors, fmt.Errorf("delete policies for site %s: %w", site, policyErr))
			continue
		}
		if err := m.drainZoneExtras(ctx, site); err != nil {
			drainErrors = append(drainErrors, err)
			continue
		}
		objects, err := m.listShardObjectIDs(ctx, site)
		if err != nil {
			drainErrors = append(drainErrors, err)
			continue
		}
		groupFailed := false
		for groupID := range groupIDs {
			if err := m.deleteDrainGroup(ctx, site, groupID, objects); err != nil {
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

// drainZoneExtras removes, or with dry-run previews, the zone-mode objects
// that the policy cache does not track: staged policy copies and the per-pair
// filter lists. Legacy sites have none.
func (m *managerImpl) drainZoneExtras(ctx context.Context, site string) error {
	if m.cachedMode(site) != "zone" {
		return nil
	}
	var errs []error
	if _, err := m.zoneMgr.DeleteStagedPolicies(ctx, site, m.cfg.DryRun); err != nil {
		errs = append(errs, err)
	}
	if _, err := m.zoneMgr.DeleteFilterTMLs(ctx, site, m.cfg.DryRun); err != nil {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("drain zone objects for site %s: %w", site, err)
	}
	return nil
}

// shardObjectIDs holds the controller IDs of a site's address groups and
// traffic matching lists.
type shardObjectIDs struct {
	groups map[string]bool
	tmls   map[string]bool
}

// listShardObjectIDs lists the site's address groups and traffic matching
// lists. The listing of the configured mode must succeed. The other kind may
// be unavailable on the controller, in which case nothing of it can exist.
func (m *managerImpl) listShardObjectIDs(ctx context.Context, site string) (shardObjectIDs, error) {
	ids := shardObjectIDs{groups: map[string]bool{}, tmls: map[string]bool{}}
	zone := m.cachedMode(site) == "zone"

	groups, groupsErr := m.ctrl.ListFirewallGroups(ctx, site)
	if groupsErr == nil {
		for _, g := range groups {
			ids.groups[g.ID] = true
		}
	}
	tmls, tmlsErr := m.ctrl.ListTrafficMatchingLists(ctx, site)
	if tmlsErr == nil {
		for _, t := range tmls {
			ids.tmls[t.ID] = true
		}
	}
	if zone && tmlsErr != nil {
		return ids, fmt.Errorf("list traffic matching lists for site %s: %w", site, tmlsErr)
	}
	if !zone && groupsErr != nil {
		return ids, fmt.Errorf("list firewall groups for site %s: %w", site, groupsErr)
	}
	return ids, nil
}

// deleteDrainGroup deletes the shard object with the given ID through the API
// of the kind that holds it. The cached ID may belong to the other kind than
// the configured mode's when the mode changed since the shard was created, and
// the controller answers a delete of an unknown ID as success, so the kind
// has to be looked up rather than discovered by a failed delete. An ID that is
// listed under neither kind is already gone.
func (m *managerImpl) deleteDrainGroup(ctx context.Context, site, id string, objects shardObjectIDs) error {
	switch {
	case objects.tmls[id]:
		return m.ctrl.DeleteTrafficMatchingList(ctx, site, id)
	case objects.groups[id]:
		return m.ctrl.DeleteFirewallGroup(ctx, site, id)
	}
	return nil
}

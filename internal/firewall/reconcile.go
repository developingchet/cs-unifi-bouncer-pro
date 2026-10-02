package firewall

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
)

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

// diffFamily reconciles one family's shard membership against desired: it adds
// IPs missing from sm and removes members no longer in desired. If ctx is
// cancelled partway through, it returns the counts accumulated so far with
// ctx.Err() appended to errs.
//
// desired was read some time ago, and decisions keep being applied while a
// large diff runs. Each change is therefore confirmed against the ban database
// just before it is made, so a ban recorded since the snapshot is not removed
// and a ban lifted since is not added back.
func (m *managerImpl) diffFamily(ctx context.Context, sm *ShardManager, desired map[string]struct{}) (added, removed int, errs []error) {
	for ip := range desired {
		if ctx.Err() != nil {
			return added, removed, append(errs, ctx.Err())
		}
		if sm.Contains(ip) {
			continue
		}
		recorded, err := m.store.BanExists(ip)
		if err != nil {
			errs = append(errs, fmt.Errorf("re-read ban %s: %w", ip, err))
			continue
		}
		if !recorded {
			continue
		}
		if _, _, err := sm.Add(ctx, ip); err != nil {
			errs = append(errs, err)
		} else {
			added++
		}
	}

	for _, ip := range sm.AllMembers() {
		if ctx.Err() != nil {
			return added, removed, append(errs, ctx.Err())
		}
		if _, ok := desired[ip]; ok {
			continue
		}
		recorded, err := m.store.BanExists(ip)
		if err != nil {
			errs = append(errs, fmt.Errorf("re-read ban %s: %w", ip, err))
			continue
		}
		if recorded {
			continue
		}
		if _, err := sm.Remove(ctx, ip); err != nil {
			errs = append(errs, err)
		} else {
			removed++
		}
	}
	return added, removed, errs
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

	// Add missing IPs, then remove extra ones, for v4.
	added, removed, errs = m.diffFamily(ctx, v4Mgr, desiredV4)
	if ctx.Err() != nil {
		return added, removed, errs
	}

	// IPv6
	if v6Mgr != nil {
		v6Added, v6Removed, v6Errs := m.diffFamily(ctx, v6Mgr, desiredV6)
		added += v6Added
		removed += v6Removed
		errs = append(errs, v6Errs...)
		if ctx.Err() != nil {
			return added, removed, errs
		}
	}

	if m.cfg.DryRun {
		if added > 0 || removed > 0 {
			m.log.Info().Str("site", site).Int("would_add", added).Int("would_remove", removed).
				Msg("[DRY-RUN] reconcile diff computed; no changes written to UniFi")
		}
		return added, removed, errs
	}

	missing, extra, writeErrs := m.reconcileWrites(ctx, site, v4Mgr, v6Mgr)
	return added + missing, removed + extra, append(errs, writeErrs...)
}

// reconcileWrites brings the controller in line with the shards' in-memory
// state: it detects out-of-band edits, flushes dirty shards, drains donors,
// prunes empty tails and repairs policies. It returns how many addresses the
// controller was missing and had in excess.
//
// It holds syncMu throughout and follows the same write gates as SyncDirty:
// nothing is written while the controller is rate limiting or the circuit
// breaker is open, and the work stops as soon as either begins. Shards left
// dirty are flushed by a later sync or reconcile.
func (m *managerImpl) reconcileWrites(ctx context.Context, site string, v4Mgr, v6Mgr *ShardManager) (missing, extra int, errs []error) {
	m.syncMu.Lock()
	defer m.syncMu.Unlock()

	if err := m.admitWrites(); err != nil {
		m.log.Info().Err(err).Str("site", site).Msg("reconcile: controller writes deferred")
		return 0, 0, []error{fmt.Errorf("reconcile writes for site %s: %w", site, err)}
	}
	defer func() {
		for _, err := range errs {
			m.noteRateLimit(err)
		}
		errs = m.settleProbe(ctx, errs)
	}()

	// Shards the bouncer considers in sync may have been edited on the
	// controller. Checked under syncMu so no flush is in flight.
	for _, mgr := range []*ShardManager{v4Mgr, v6Mgr} {
		if mgr == nil {
			continue
		}
		if m.writesPaused() != nil {
			break
		}
		gone, surplus, err := mgr.MarkRemoteDrift(ctx)
		if err != nil {
			m.noteRateLimit(err)
			errs = append(errs, fmt.Errorf("check controller membership for site %s: %w", site, err))
			continue
		}
		missing += gone
		extra += surplus
	}
	if m.writesPaused() != nil {
		return missing, extra, errs
	}

	flushed, flushErrs := m.flushReconciled(ctx, v4Mgr, v6Mgr)
	errs = append(errs, flushErrs...)
	if m.writesPaused() != nil {
		return missing, extra, errs
	}

	// Donor shards keep their policies until every target has been
	// flushed, so draining and pruning wait for a clean flush.
	if flushed {
		errs = append(errs, m.drainReconciled(ctx, v4Mgr, v6Mgr)...)
		m.pruneEmptyTailShards(ctx, site, v4Mgr, v6Mgr)
		if m.writesPaused() != nil {
			return missing, extra, errs
		}
	}

	// Membership alone does not enforce bans. Repair policies/rules that were
	// deleted externally or missed when an activation callback failed. This
	// runs even when one shard failed to flush: that shard has no ID yet
	// and is skipped, and every other shard still gets its policy.
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
	return missing, extra, errs
}

// flushReconciled flushes the dirty shards of both families and reports
// whether every family was flushed.
func (m *managerImpl) flushReconciled(ctx context.Context, v4Mgr, v6Mgr *ShardManager) (bool, []error) {
	var errs []error
	flushed := true
	for _, f := range []struct {
		name string
		sm   *ShardManager
	}{{"v4", v4Mgr}, {"v6", v6Mgr}} {
		if f.sm == nil {
			continue
		}
		if m.writesPaused() != nil {
			return false, errs
		}
		if err := f.sm.syncAllFamilies(ctx); err != nil {
			errs = append(errs, fmt.Errorf("%s flush: %w", f.name, err))
			flushed = false
		}
	}
	return flushed, errs
}

// drainReconciled removes the drained donor shards of both families.
func (m *managerImpl) drainReconciled(ctx context.Context, v4Mgr, v6Mgr *ShardManager) []error {
	var errs []error
	if err := v4Mgr.drainDraining(ctx); err != nil {
		errs = append(errs, fmt.Errorf("drain v4 shards: %w", err))
	}
	if v6Mgr != nil {
		if err := v6Mgr.drainDraining(ctx); err != nil {
			errs = append(errs, fmt.Errorf("drain v6 shards: %w", err))
		}
	}
	return errs
}

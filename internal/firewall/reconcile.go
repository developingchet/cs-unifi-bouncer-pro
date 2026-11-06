package firewall

import (
	"context"
	"fmt"
)

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
	defer m.saveSiteShardRecords(site, v4Mgr, v6Mgr)

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
		} else if err := m.retryConvertedRules(ctx, site); err != nil {
			errs = append(errs, fmt.Errorf("retire converted legacy rules for site %s: %w", site, err))
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

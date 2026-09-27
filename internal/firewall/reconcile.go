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
func (m *managerImpl) diffFamily(ctx context.Context, sm *ShardManager, desired map[string]struct{}) (added, removed int, errs []error) {
	for ip := range desired {
		if ctx.Err() != nil {
			return added, removed, append(errs, ctx.Err())
		}
		if !sm.Contains(ip) {
			if _, _, err := sm.Add(ctx, ip); err != nil {
				errs = append(errs, err)
			} else {
				added++
			}
		}
	}

	for _, ip := range sm.AllMembers() {
		if ctx.Err() != nil {
			return added, removed, append(errs, ctx.Err())
		}
		if _, ok := desired[ip]; !ok {
			if _, err := sm.Remove(ctx, ip); err != nil {
				errs = append(errs, err)
			} else {
				removed++
			}
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
	} else {
		func() {
			m.syncMu.Lock()
			defer m.syncMu.Unlock()
			// Shards the bouncer considers in sync may have been edited on the
			// controller. Checked under syncMu so no flush is in flight.
			for _, mgr := range []*ShardManager{v4Mgr, v6Mgr} {
				if mgr == nil {
					continue
				}
				missing, extra, err := mgr.MarkRemoteDrift(ctx)
				if err != nil {
					errs = append(errs, fmt.Errorf("check controller membership for site %s: %w", site, err))
					continue
				}
				added += missing
				removed += extra
			}
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
			// Donor shards keep their policies until every target has been
			// flushed, so draining and pruning wait for a clean flush.
			if flushed {
				if err := v4Mgr.drainDraining(ctx); err != nil {
					errs = append(errs, fmt.Errorf("drain v4 shards: %w", err))
				}
				if v6Mgr != nil {
					if err := v6Mgr.drainDraining(ctx); err != nil {
						errs = append(errs, fmt.Errorf("drain v6 shards: %w", err))
					}
				}
				m.pruneEmptyTailShards(ctx, site, v4Mgr, v6Mgr)
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
		}()
	}

	return
}

package firewall

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
)

// desiredBans is the ban database split by address family.
type desiredBans struct {
	v4, v6 map[string]struct{}
}

// Reconcile performs a full diff between bbolt state and UniFi API state.
// The ban list is read once for all sites.
func (m *managerImpl) Reconcile(ctx context.Context, sites []string) (*ReconcileResult, error) {
	ctx, endPass := controller.BeginPass(ctx)
	defer endPass()
	start := time.Now()
	result := &ReconcileResult{}

	desired, err := m.loadDesiredBans()
	if err != nil {
		result.Errors = []error{err}
		result.Elapsed = time.Since(start)
		return result, err
	}
	for _, site := range sites {
		added, removed, errs := m.reconcileSite(ctx, site, desired)
		result.Added += added
		result.Removed += removed
		result.Errors = append(result.Errors, errs...)

		metrics.ReconcileDelta.WithLabelValues("added", site).Set(float64(added))
		metrics.ReconcileDelta.WithLabelValues("removed", site).Set(float64(removed))
	}

	result.Elapsed = time.Since(start)
	return result, errors.Join(result.Errors...)
}

// loadDesiredBans reads the ban database into one address set per family.
func (m *managerImpl) loadDesiredBans() (desiredBans, error) {
	bans, err := m.store.BanList()
	if err != nil {
		return desiredBans{}, fmt.Errorf("load ban list: %w", err)
	}
	desired := desiredBans{v4: make(map[string]struct{}), v6: make(map[string]struct{})}
	for ip, entry := range bans {
		if entry.IPv6 {
			desired.v6[ip] = struct{}{}
		} else {
			desired.v4[ip] = struct{}{}
		}
	}
	return desired, nil
}

// reconcileSite diffs the ban database against all UniFi groups for one site.
func (m *managerImpl) reconcileSite(ctx context.Context, site string, desired desiredBans) (added, removed int, errs []error) {
	v4Mgr, v6Mgr := m.siteShardMgrs(site)
	if v4Mgr == nil {
		return
	}

	added, removed, errs = m.diffFamily(ctx, v4Mgr, desired.v4)
	if ctx.Err() != nil {
		return added, removed, errs
	}
	if v6Mgr != nil {
		v6Added, v6Removed, v6Errs := m.diffFamily(ctx, v6Mgr, desired.v6)
		added += v6Added
		removed += v6Removed
		errs = append(errs, v6Errs...)
		if ctx.Err() != nil {
			return added, removed, errs
		}
	}

	m.refreshShardMetrics([]string{site})
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

// diffFamily reconciles one family's shard membership against desired: it adds
// IPs missing from sm and removes members no longer in desired. If ctx is
// cancelled partway through, it returns the counts accumulated so far with
// ctx.Err() appended to errs.
//
// desired was read some time ago, and decisions keep being applied while a
// large diff runs. The differences are therefore confirmed against the ban
// database, read again after the shard membership was, so a ban recorded since
// the snapshot is not removed and a ban lifted since is not added back. A ban
// is recorded before its address joins a shard and deleted after it leaves, so
// that order catches every change made before the re-read. The re-read takes
// keys only, and is skipped when nothing differs.
func (m *managerImpl) diffFamily(ctx context.Context, sm *ShardManager, desired map[string]struct{}) (added, removed int, errs []error) {
	var missing, extra []string
	for ip := range desired {
		if !sm.Contains(ip) {
			missing = append(missing, ip)
		}
	}
	for _, ip := range sm.AllMembers() {
		if _, ok := desired[ip]; !ok {
			extra = append(extra, ip)
		}
	}
	if len(missing) == 0 && len(extra) == 0 {
		return 0, 0, nil
	}
	if err := ctx.Err(); err != nil {
		return 0, 0, []error{err}
	}
	recorded, err := m.store.BanKeys()
	if err != nil {
		return 0, 0, []error{fmt.Errorf("re-read ban database: %w", err)}
	}

	for _, ip := range missing {
		if ctx.Err() != nil {
			return added, removed, append(errs, ctx.Err())
		}
		if _, ok := recorded[ip]; !ok {
			continue
		}
		if _, err := sm.Add(ctx, ip); err != nil {
			errs = append(errs, err)
		} else {
			added++
		}
	}
	for _, ip := range extra {
		if ctx.Err() != nil {
			return added, removed, append(errs, ctx.Err())
		}
		if _, ok := recorded[ip]; ok {
			continue
		}
		if err := sm.Remove(ctx, ip); err != nil {
			errs = append(errs, err)
		} else {
			removed++
		}
	}
	return added, removed, errs
}

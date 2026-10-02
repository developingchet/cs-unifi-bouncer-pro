package firewall

import (
	"context"
	"errors"
	"fmt"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
)

// DeleteStagedPolicies removes the staged replacement copies of block
// policies from site. They are created under a temporary name that is never
// cached, so a drain driven by the policy cache would leave them behind, still
// referencing the shard lists. With dryRun it only logs what would be
// deleted. It returns the number of policies deleted or previewed.
func (zm *ZoneManager) DeleteStagedPolicies(ctx context.Context, site string, dryRun bool) (int, error) {
	zm.opMu.Lock()
	defer zm.opMu.Unlock()
	policies, err := zm.ctrl.ListZonePolicies(ctx, site)
	if err != nil {
		return 0, fmt.Errorf("list zone policies for site %s: %w", site, err)
	}
	var errs []error
	n := 0
	for _, p := range policies {
		if !zm.isStagedPolicy(p) {
			continue
		}
		if dryRun {
			zm.log.Info().Str("site", site).Str("policy", p.Name).Msg("[DRY-RUN] would delete staged zone policy")
			n++
			continue
		}
		if err := zm.ctrl.DeleteZonePolicy(ctx, site, p.ID); err != nil {
			var missing *controller.ErrNotFound
			if !errors.As(err, &missing) {
				errs = append(errs, fmt.Errorf("delete staged zone policy %s: %w", p.Name, err))
				continue
			}
		}
		zm.log.Info().Str("site", site).Str("policy", p.Name).Msg("deleted staged zone policy")
		n++
	}
	return n, errors.Join(errs...)
}

// DeleteFilterTMLs removes the per-pair port and destination-IP lists from
// site once no policy of anyone else refers to them. The block policies are
// expected to be gone already; those still listed are ignored when working
// out what is referenced, so a preview agrees with the real run. With dryRun
// it only logs what would be deleted. It returns the number of lists deleted
// or previewed.
func (zm *ZoneManager) DeleteFilterTMLs(ctx context.Context, site string, dryRun bool) (int, error) {
	zm.opMu.Lock()
	defer zm.opMu.Unlock()
	tmls, err := zm.ctrl.ListTrafficMatchingLists(ctx, site)
	if err != nil {
		return 0, fmt.Errorf("list traffic matching lists for site %s: %w", site, err)
	}
	policies, err := zm.ctrl.ListZonePolicies(ctx, site)
	if err != nil {
		return 0, fmt.Errorf("list zone policies for site %s: %w", site, err)
	}
	referenced := make(map[string]bool)
	for _, p := range policies {
		if zm.ownsBlockPolicy(p) || zm.isStagedPolicy(p) {
			continue
		}
		referenced[p.SrcPortTMLID] = true
		referenced[p.DstPortTMLID] = true
		referenced[p.DstIPTMLID] = true
	}
	var errs []error
	n := 0
	for _, t := range tmls {
		if !isFilterTMLName(t.Name) {
			continue
		}
		if referenced[t.ID] {
			zm.log.Warn().Str("site", site).Str("tml", t.Name).
				Msg("filter list is still used by a policy this bouncer does not own; keeping it")
			continue
		}
		if dryRun {
			zm.log.Info().Str("site", site).Str("tml", t.Name).Msg("[DRY-RUN] would delete filter list")
			n++
			continue
		}
		if err := zm.ctrl.DeleteTrafficMatchingList(ctx, site, t.ID); err != nil {
			errs = append(errs, fmt.Errorf("delete filter list %s: %w", t.Name, err))
			continue
		}
		zm.log.Info().Str("site", site).Str("tml", t.Name).Msg("deleted filter list")
		n++
	}
	return n, errors.Join(errs...)
}

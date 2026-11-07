package firewall

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
)

// isStagedPolicy reports whether p is a staged replacement copy owned by this
// bouncer: an inbound copy with one source list, or an egress copy with none
// and the shard list as its destination.
func (zm *ZoneManager) isStagedPolicy(p controller.ZonePolicy) bool {
	listed := len(p.TrafficMatchingListIDs) == 1 || (len(p.TrafficMatchingListIDs) == 0 && p.DstIPTMLID != "")
	return strings.HasPrefix(p.Name, stagedPolicyPrefix) && p.Action == "BLOCK" &&
		p.Description == zm.cfg.Description && listed
}

// cleanupStagedPolicies settles the staged copies a replacement left behind.
// A staged copy is the only block on its shard while the replacement is
// incomplete, so it is deleted only when it has become redundant:
//
//   - a block policy under its own name now covers the same group, zones, IP
//     version and filters, which means the replacement completed; or
//   - its group is not one of owned, so there is no shard left to block.
//
// Any other staged copy stays and is reused when the replacement is retried.
// existingByID is the site's current policy list and is kept up to date.
func (zm *ZoneManager) cleanupStagedPolicies(ctx context.Context, site string, owned map[string]bool,
	existingByID map[string]controller.ZonePolicy,
) error {
	var errs []error
	for _, staged := range existingByID {
		if !zm.isStagedPolicy(staged) {
			continue
		}
		covered := coveredByNamedPolicy(staged, existingByID)
		if !covered && owned[policyListID(staged)] {
			continue
		}
		if err := zm.deleteStagedPolicy(ctx, site, staged, existingByID); err != nil {
			errs = append(errs, err)
			continue
		}
		zm.log.Info().Str("policy", staged.Name).Str("site", site).Bool("replacement_complete", covered).
			Msg("deleted staged zone policy that is no longer needed")
	}
	return errors.Join(errs...)
}

// coveredByNamedPolicy reports whether a block policy other than a staged
// copy applies to the same group, zones, IP version and filters as staged. A
// policy with different filters is the one the staged copy is replacing.
func coveredByNamedPolicy(staged controller.ZonePolicy, existingByID map[string]controller.ZonePolicy) bool {
	for _, p := range existingByID {
		if p.ID == staged.ID || strings.HasPrefix(p.Name, stagedPolicyPrefix) || p.Action != "BLOCK" {
			continue
		}
		if slices.Equal(p.TrafficMatchingListIDs, staged.TrafficMatchingListIDs) &&
			p.SrcZone == staged.SrcZone && p.DstZone == staged.DstZone && p.IPVersion == staged.IPVersion &&
			p.SrcPortTMLID == staged.SrcPortTMLID && p.DstPortTMLID == staged.DstPortTMLID && p.DstIPTMLID == staged.DstIPTMLID {
			return true
		}
	}
	return false
}

// ownedGroupIDs returns the controller IDs of the shards of both families
// that currently exist.
func ownedGroupIDs(v4Shards, v6Shards *ShardManager) map[string]bool {
	ids := make(map[string]bool)
	for _, sm := range []*ShardManager{v4Shards, v6Shards} {
		if sm == nil {
			continue
		}
		for _, ref := range sm.OwnedRefs() {
			ids[ref.ID] = true
		}
	}
	return ids
}

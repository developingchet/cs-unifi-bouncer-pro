package firewall

import (
	"slices"
	"strings"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
)

// shadowingAllow is an ALLOW policy the controller evaluates before an egress
// block policy for the same zones, so the hosts it allows can still reach
// banned addresses.
type shadowingAllow struct {
	allow, block controller.ZonePolicy
}

// recordZonePolicies counts the expected block policies the site holds per
// direction and reports ALLOW policies that precede an egress block.
// existingByID is the listing EnsurePolicies worked from, including the
// policies it created.
func (zm *ZoneManager) recordZonePolicies(site string, expectedNames map[string]bool, existingByID map[string]controller.ZonePolicy) {
	inbound, egress := 0, 0
	var blocks []controller.ZonePolicy
	for _, p := range existingByID {
		if !expectedNames[p.Name] {
			continue
		}
		if zm.isEgressPolicyName(p.Name) {
			egress++
			blocks = append(blocks, p)
			continue
		}
		inbound++
	}
	metrics.ZoneBlockPolicies.WithLabelValues("inbound", site).Set(float64(inbound))
	metrics.ZoneBlockPolicies.WithLabelValues("egress", site).Set(float64(egress))
	zm.reportShadowingAllows(site, shadowingAllows(zm.cfg.Description, blocks, existingByID))
}

// hasEgressPairs reports whether pairs include an EGRESS_ZONE_PAIRS pair.
func hasEgressPairs(pairs []config.ZonePair) bool {
	return slices.ContainsFunc(pairs, func(p config.ZonePair) bool { return p.Egress })
}

// isEgressPolicyName reports whether name is an egress block policy name.
func (zm *ZoneManager) isEgressPolicyName(name string) bool {
	return strings.HasPrefix(name, zm.namer.PolicyPrefix()+egressMarker)
}

// shadowingAllows lists the enabled ALLOW policies not managed by the bouncer
// that the controller evaluates before one of the egress blocks for the same
// zones and address family. Policies without a reported order are skipped:
// the order cannot be checked.
func shadowingAllows(description string, blocks []controller.ZonePolicy, existingByID map[string]controller.ZonePolicy) []shadowingAllow {
	var found []shadowingAllow
	for _, block := range blocks {
		if block.Index == nil {
			continue
		}
		for _, p := range existingByID {
			if !p.Enabled || p.Action != "ALLOW" || p.Description == description || p.Index == nil ||
				p.SrcZone != block.SrcZone || p.DstZone != block.DstZone {
				continue
			}
			if p.IPVersion != "" && p.IPVersion != "BOTH" && p.IPVersion != block.IPVersion {
				continue
			}
			if *p.Index < *block.Index {
				found = append(found, shadowingAllow{allow: p, block: block})
			}
		}
	}
	slices.SortFunc(found, func(a, b shadowingAllow) int {
		if c := strings.Compare(a.block.Name, b.block.Name); c != 0 {
			return c
		}
		return strings.Compare(a.allow.Name, b.allow.Name)
	})
	return found
}

// reportShadowingAllows warns about each ALLOW that precedes an egress block.
// The bouncer cannot fix the order itself: recreating its block would move it
// further back. A site's warnings are repeated only when the set changes.
func (zm *ZoneManager) reportShadowingAllows(site string, found []shadowingAllow) {
	keys := make([]string, 0, len(found))
	for _, s := range found {
		keys = append(keys, s.allow.ID+">"+s.block.ID)
	}
	key := strings.Join(keys, ",")
	zm.mu.Lock()
	if zm.egressOrderReported == nil {
		zm.egressOrderReported = make(map[string]string)
	}
	unchanged := zm.egressOrderReported[site] == key
	zm.egressOrderReported[site] = key
	zm.mu.Unlock()
	if unchanged {
		return
	}
	for _, s := range found {
		zm.log.Warn().Str("site", site).Str("allow", s.allow.Name).Str("block", s.block.Name).
			Msg("an ALLOW policy is evaluated before an egress block policy for the same zones; hosts it allows can still connect to banned addresses until the ALLOW is moved after the block")
	}
}

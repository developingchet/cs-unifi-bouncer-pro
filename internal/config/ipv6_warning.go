package config

import (
	"fmt"
	"net/netip"
	"strings"
)

// UnenforcedIPv6Warnings returns a warning for each of sites where IPv6 bans
// are on but no zone pair can carry an IPv6 block policy: every inbound pair
// the site uses is limited to IPv4 destination addresses and the site has no
// egress pair. A zone-based site then keeps IPv6 bans in a shard list that no
// policy uses. Legacy sites block IPv6 through their WANv6_IN rule, so the
// warning applies only if the site uses the zone-based firewall. It returns
// nothing when the pairs do not parse (validation reports that).
func (c *Config) UnenforcedIPv6Warnings(sites []string) []string {
	if !c.FirewallEnableIPv6 || c.FirewallMode == "legacy" {
		return nil
	}
	inbound, err := c.ParseZonePairs()
	if err != nil {
		return nil
	}
	egress, err := c.ParseEgressZonePairs()
	if err != nil {
		return nil
	}
	var warnings []string
	for _, site := range sites {
		if len(PairsForSite(egress, site)) > 0 {
			continue
		}
		pairs := PairsForSite(inbound, site)
		if len(pairs) == 0 || !allIPv4Only(pairs) {
			continue
		}
		warnings = append(warnings, fmt.Sprintf("FIREWALL_ENABLE_IPV6 is on, but every ZONE_PAIRS pair of site %q is limited to IPv4 "+
			"destination addresses and the site has no EGRESS_ZONE_PAIRS pair, so if it uses the zone-based firewall it has "+
			"no policy to enforce IPv6 bans; set FIREWALL_ENABLE_IPV6=false or add a pair that IPv6 traffic can match", site))
	}
	return warnings
}

func allIPv4Only(pairs []ZonePair) bool {
	for _, p := range pairs {
		if !ipv4Only(p.DstIPs) {
			return false
		}
	}
	return true
}

// ipv4Only reports whether ips is non-empty and every entry, a plain address
// or a CIDR, is IPv4.
func ipv4Only(ips []string) bool {
	if len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		addr, _, _ := strings.Cut(ip, "/")
		parsed, err := netip.ParseAddr(addr)
		if err != nil || !parsed.Unmap().Is4() {
			return false
		}
	}
	return true
}

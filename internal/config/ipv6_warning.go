package config

import (
	"net/netip"
	"strings"
)

// UnenforcedIPv6Warning returns a warning when IPv6 bans are on but no zone
// pair can carry an IPv6 block policy: every inbound pair is limited to IPv4
// destination addresses and there is no egress pair. Zone-based sites then
// keep IPv6 bans in a shard list that no policy uses. Legacy sites block IPv6
// through their WANv6_IN rule, so the warning names zone-based sites only.
// It returns "" otherwise, or when the pairs do not parse (validation reports
// that).
func (c *Config) UnenforcedIPv6Warning() string {
	if !c.FirewallEnableIPv6 || c.FirewallMode == "legacy" {
		return ""
	}
	inbound, err := c.ParseZonePairs()
	if err != nil || len(inbound) == 0 {
		return ""
	}
	egress, err := c.ParseEgressZonePairs()
	if err != nil || len(egress) > 0 {
		return ""
	}
	for _, p := range inbound {
		if !ipv4Only(p.DstIPs) {
			return ""
		}
	}
	return "FIREWALL_ENABLE_IPV6 is on, but every ZONE_PAIRS pair is limited to IPv4 destination addresses, " +
		"so zone-based sites have no policy to enforce IPv6 bans; set FIREWALL_ENABLE_IPV6=false " +
		"or add a pair that IPv6 traffic can match"
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

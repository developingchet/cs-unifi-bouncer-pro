package config

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ZonePair represents a parsed src->dst zone pair, optionally with port and IP filters.
type ZonePair struct {
	// Site is the UniFi site named by a "<site>/" prefix, or "" for a pair
	// without one. See SitePairs for how the two kinds combine.
	Site     string
	Src      string
	Dst      string
	SrcPorts []int    // empty = any source ports
	DstPorts []int    // empty = any destination ports
	DstIPs   []string // empty = any destination IPs; CIDRs or plain IPs, IPv4 or IPv6
	// Egress marks a pair from EGRESS_ZONE_PAIRS: its block policies match
	// the ban list as the destination instead of the source.
	Egress bool
}

// parseZoneSide parses "zoneName[:port1,port2,...]" and returns the zone name
// and optional port list. A bare zone name (no colon) returns nil ports.
func parseZoneSide(side string) (zoneName string, ports []int, err error) {
	idx := strings.Index(side, ":")
	if idx == -1 {
		if side == "" {
			return "", nil, fmt.Errorf("zone name must not be empty")
		}
		if strings.Contains(side, ",") {
			return "", nil, fmt.Errorf("unexpected comma in zone name %q; separate pairs with semicolons when using port or destination IP lists", side)
		}
		return side, nil, nil
	}
	zoneName = side[:idx]
	if zoneName == "" {
		return "", nil, fmt.Errorf("zone name must not be empty")
	}
	portStr := side[idx+1:]
	if portStr == "" {
		return "", nil, fmt.Errorf("port list after ':' must not be empty")
	}
	portParts := strings.Split(portStr, ",")
	ports = make([]int, 0, len(portParts))
	for _, ps := range portParts {
		ps = strings.TrimSpace(ps)
		if ps == "" {
			return "", nil, fmt.Errorf("empty port in port list")
		}
		n, parseErr := strconv.Atoi(ps)
		if parseErr != nil {
			return "", nil, fmt.Errorf("invalid port %q: must be an integer", ps)
		}
		if n < 1 || n > 65535 {
			return "", nil, fmt.Errorf("port %d out of range (must be 1-65535)", n)
		}
		ports = append(ports, n)
	}
	return zoneName, ports, nil
}

// parseZonePairList parses zone pair strings in
// "[site/]src[:port,...]->dst[:port,...][@ip1,ip2,...]" format.
func parseZonePairList(pairs []string) ([]ZonePair, error) {
	result := make([]ZonePair, 0, len(pairs))
	for _, p := range pairs {
		if strings.Count(p, "->") != 1 {
			return nil, fmt.Errorf("invalid zone pair %q: expected one src->dst pair; separate pairs with semicolons when using comma-separated ports or destination IPs", p)
		}
		site, body, err := cutSitePrefix(p)
		if err != nil {
			return nil, fmt.Errorf("invalid zone pair %q: %w", p, err)
		}
		parts := strings.SplitN(body, "->", 2)
		src, srcPorts, err := parseZoneSide(strings.TrimSpace(parts[0]))
		if err != nil {
			return nil, fmt.Errorf("invalid zone pair %q src: %w", p, err)
		}

		// Split dst on '@' to extract optional destination IP list.
		dstRaw := strings.TrimSpace(parts[1])
		var dstIPs []string
		if idx := strings.Index(dstRaw, "@"); idx != -1 {
			ipPart := strings.TrimSpace(dstRaw[idx+1:])
			dstRaw = dstRaw[:idx]
			for _, ip := range strings.Split(ipPart, ",") {
				ip = strings.TrimSpace(ip)
				if ip == "" {
					return nil, fmt.Errorf("invalid zone pair %q: empty destination IP after @", p)
				}
				if strings.Contains(ip, "/") {
					if _, _, cidrErr := net.ParseCIDR(ip); cidrErr != nil {
						return nil, fmt.Errorf("invalid zone pair %q: invalid dst CIDR %q: %w", p, ip, cidrErr)
					}
				} else {
					if net.ParseIP(ip) == nil {
						return nil, fmt.Errorf("invalid zone pair %q: invalid dst IP %q", p, ip)
					}
				}
				dstIPs = append(dstIPs, ip)
			}
		}

		dst, dstPorts, err := parseZoneSide(dstRaw)
		if err != nil {
			return nil, fmt.Errorf("invalid zone pair %q dst: %w", p, err)
		}
		result = append(result, ZonePair{Site: site, Src: src, Dst: dst, SrcPorts: srcPorts, DstPorts: dstPorts, DstIPs: dstIPs})
	}
	return result, nil
}

// ParseZonePairs parses ZONE_PAIRS in "src[:port,...]->dst[:port,...]" format.
func (c *Config) ParseZonePairs() ([]ZonePair, error) {
	return parseZonePairList(c.ZonePairs)
}

// ParseCloudflareZonePairs parses CLOUDFLARE_ZONE_PAIRS in "src[:port,...]->dst[:port,...]" format.
func (c *Config) ParseCloudflareZonePairs() ([]ZonePair, error) {
	return parseZonePairList(c.CloudflareZonePairs)
}

// ParseEgressZonePairs parses EGRESS_ZONE_PAIRS in "src[:port,...]->dst[:port,...]"
// format and marks each pair as egress. A destination IP list ("@...") is
// rejected: the ban list is the destination filter of an egress policy.
func (c *Config) ParseEgressZonePairs() ([]ZonePair, error) {
	pairs, err := parseZonePairList(c.EgressZonePairs)
	if err != nil {
		return nil, err
	}
	for i := range pairs {
		if len(pairs[i].DstIPs) > 0 {
			return nil, fmt.Errorf("invalid zone pair %q: an egress pair matches banned addresses as the destination and cannot take a destination IP list", c.EgressZonePairs[i])
		}
		pairs[i].Egress = true
	}
	return pairs, nil
}

// ManagedZonePairs returns the ZONE_PAIRS pairs followed by the
// EGRESS_ZONE_PAIRS pairs: every pair the zone manager keeps block policies for.
func (c *Config) ManagedZonePairs() ([]ZonePair, error) {
	pairs, err := c.ParseZonePairs()
	if err != nil {
		return nil, fmt.Errorf("ZONE_PAIRS: %w", err)
	}
	egress, err := c.ParseEgressZonePairs()
	if err != nil {
		return nil, fmt.Errorf("EGRESS_ZONE_PAIRS: %w", err)
	}
	return append(pairs, egress...), nil
}

// joinZonePairLines turns a zone pair file into the ZONE_PAIRS syntax. Each
// line holds one pair, or a list in the variable's own syntax; blank lines and
// lines starting with # are skipped. Several lines are joined with semicolons,
// so a line may carry port and destination IP lists with commas.
func joinZonePairLines(content string) string {
	var pairs []string
	for line := range strings.Lines(content) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// A comma list on one line splits here, before the semicolon join
		// would make its commas read as port lists.
		pairs = append(pairs, splitZonePairList(line)...)
	}
	return strings.Join(pairs, ";")
}

// splitZonePairList splits a zone-pair list string into individual zone pair
// strings. It handles two formats:
//
//  1. Semicolon-separated (required when any pair contains port lists):
//     "External:80,443->Internal;External->DMZ"
//
//  2. Comma-separated without port syntax (backward-compatible):
//     "wan->lan,wan->iot,wan->dmz"
//
// If the string contains semicolons, it is always split on semicolons.
// Otherwise, if every comma-separated part contains "->", the commas are
// treated as zone-pair separators (old-style format). If any part lacks "->",
// the entire string is treated as a single zone pair (commas are port
// separators within that pair, e.g. "External:80,443->Internal:80,443").
func splitZonePairList(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}

	// Prefer semicolons — unambiguous with port-list commas.
	if strings.Contains(s, ";") {
		parts := strings.Split(s, ";")
		result := make([]string, 0, len(parts))
		for _, p := range parts {
			// Keep empty entries so a stray separator is reported, not ignored.
			result = append(result, strings.TrimSpace(p))
		}
		return result
	}

	// Try comma split: only use it when every part contains "->" so we know
	// the commas are zone-pair separators, not port-list separators.
	parts := strings.Split(s, ",")
	allHaveArrow := true
	for _, p := range parts {
		if !strings.Contains(strings.TrimSpace(p), "->") {
			allHaveArrow = false
			break
		}
	}
	if allHaveArrow {
		result := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				result = append(result, p)
			}
		}
		return result
	}

	// Commas are port-list separators — the whole string is a single zone pair.
	return []string{s}
}

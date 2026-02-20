package decision

import (
	"fmt"
	"net"
	"strings"
)

// ParseAndSanitize parses an IP or CIDR string and returns the canonical form.
// Returns an error for unparseable inputs.
func ParseAndSanitize(value string) (string, bool, error) {
	value = strings.TrimSpace(value)

	// Try CIDR first
	if strings.Contains(value, "/") {
		ip, network, err := net.ParseCIDR(value)
		if err != nil {
			return "", false, fmt.Errorf("invalid CIDR %q: %w", value, err)
		}
		_ = ip
		return network.String(), true, nil
	}

	// Try plain IP
	ip := net.ParseIP(value)
	if ip == nil {
		return "", false, fmt.Errorf("invalid IP address %q", value)
	}

	// Detect IPv4-mapped IPv6 (e.g. ::ffff:1.2.3.4) and normalize to IPv4
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String(), false, nil
	}
	return ip.String(), false, nil
}

// IsIPv6 returns true if the string is an IPv6 address or CIDR.
func IsIPv6(value string) bool {
	if strings.Contains(value, "/") {
		ip, _, err := net.ParseCIDR(value)
		if err != nil {
			return false
		}
		return ip.To4() == nil
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return false
	}
	return ip.To4() == nil
}

// IsPrivate returns true if the IP/CIDR is RFC1918, loopback, link-local, or ULA.
func IsPrivate(value string) bool {
	var ip net.IP
	if strings.Contains(value, "/") {
		parsedIP, _, err := net.ParseCIDR(value)
		if err != nil {
			return false
		}
		ip = parsedIP
	} else {
		ip = net.ParseIP(value)
	}
	if ip == nil {
		return false
	}

	// Normalize to 16-byte form for consistent checking
	ip16 := ip.To16()

	for _, block := range privateBlocks {
		if block.Contains(ip16) {
			return true
		}
	}
	return false
}

// privateBlocks contains all RFC-private, loopback, link-local, and ULA ranges.
var privateBlocks = func() []*net.IPNet {
	cidrs := []string{
		// IPv4
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"100.64.0.0/10", // CGNAT (RFC 6598)
		// IPv4-mapped in IPv6
		"::ffff:10.0.0.0/104",
		"::ffff:172.16.0.0/108",
		"::ffff:192.168.0.0/112",
		"::ffff:127.0.0.0/104",
		// IPv6
		"::1/128",   // loopback
		"fe80::/10", // link-local
		"fc00::/7",  // ULA (fc00::/8 and fd00::/8)
		"100::/64",  // Teredo
	}
	blocks := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic("invalid private CIDR: " + cidr)
		}
		blocks = append(blocks, block)
	}
	return blocks
}()

// IsWhitelisted checks if ip is covered by any of the whitelist CIDR entries.
func IsWhitelisted(ip string, whitelist []*net.IPNet) bool {
	var parsed net.IP
	if strings.Contains(ip, "/") {
		// For CIDR decisions, check if the network address is whitelisted
		p, _, err := net.ParseCIDR(ip)
		if err != nil {
			return false
		}
		parsed = p
	} else {
		parsed = net.ParseIP(ip)
		if parsed == nil {
			return false
		}
	}

	for _, wl := range whitelist {
		if wl.Contains(parsed) {
			return true
		}
	}
	return false
}

// ParseWhitelist parses a slice of IP/CIDR strings into net.IPNet entries.
func ParseWhitelist(entries []string) ([]*net.IPNet, error) {
	result := make([]*net.IPNet, 0, len(entries))
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if !strings.Contains(e, "/") {
			// Single IP: convert to /32 or /128
			ip := net.ParseIP(e)
			if ip == nil {
				return nil, fmt.Errorf("invalid whitelist entry %q", e)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			e = fmt.Sprintf("%s/%d", ip.String(), bits)
		}
		_, cidr, err := net.ParseCIDR(e)
		if err != nil {
			return nil, fmt.Errorf("invalid whitelist CIDR %q: %w", e, err)
		}
		result = append(result, cidr)
	}
	return result, nil
}

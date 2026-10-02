package whitelist

import (
	"fmt"
	"net/netip"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/decision"
)

// The Cloudflare list becomes an allow rule that sits ahead of the block
// rules, so a corrupted or hijacked response must not be able to open the
// firewall to the internet or to an internal network. Cloudflare's own ranges
// are no broader than a /13 (IPv4) and a /29 (IPv6), and each list holds
// about ten entries.
const (
	minCloudflarePrefixV4 = 12
	minCloudflarePrefixV6 = 29
	maxCloudflareEntries  = 1000
)

// nonPublicPrefixes are ranges beyond the private and loopback blocks that
// decision.IsPrivate covers, which no Cloudflare edge address belongs to.
var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/3"), // multicast, reserved and broadcast
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::ffff:0:0/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("ff00::/8"),
}

// validateCloudflarePrefix rejects a prefix that is too broad to be a
// Cloudflare range, or that covers a non-public network.
func validateCloudflarePrefix(prefix netip.Prefix) error {
	minBits := minCloudflarePrefixV4
	if prefix.Addr().Is6() {
		minBits = minCloudflarePrefixV6
	}
	if prefix.Bits() < minBits {
		return fmt.Errorf("prefix is broader than /%d", minBits)
	}
	if decision.IsPrivate(prefix.String()) {
		return fmt.Errorf("prefix covers a private or loopback network")
	}
	for _, bogon := range nonPublicPrefixes {
		if bogon.Overlaps(prefix) {
			return fmt.Errorf("prefix overlaps non-public range %s", bogon)
		}
	}
	return nil
}

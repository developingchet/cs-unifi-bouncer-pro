package feedhttp

import (
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

// internalPrefixes are ranges that are not covered by the netip predicates
// but never hold a public feed host: carrier-grade NAT, "this network",
// IETF protocol assignments, benchmarking, reserved space, and the IPv6
// translation and tunnelling prefixes that embed an IPv4 address.
var internalPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("fec0::/10"),
}

// IsInternalAddr reports whether addr points at the local host or a private,
// link-local, multicast, reserved or otherwise non-public network. An
// IPv4-mapped IPv6 address is judged by the IPv4 address it carries.
func IsInternalAddr(addr netip.Addr) bool {
	addr = addr.Unmap().WithZone("")
	if !addr.IsValid() {
		return true
	}
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsUnspecified() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() {
		return true
	}
	for _, prefix := range internalPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// sameOrigin reports whether a and b share scheme, host and port. A feed
// configured on an internal host may redirect within that host; the checks
// for internal addresses only matter once a redirect leaves it.
func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		normalizeHost(a.Hostname()) == normalizeHost(b.Hostname()) &&
		effectivePort(a) == effectivePort(b)
}

func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	return "80"
}

// originalRequest returns the request the caller made, found by following
// Response links back through the redirects that led to req.
func originalRequest(req *http.Request) *http.Request {
	for req.Response != nil && req.Response.Request != nil {
		req = req.Response.Request
	}
	return req
}

// normalizeHost lower-cases a URL host name and drops the trailing dot of a
// fully qualified name, so "LOCALHOST." compares equal to "localhost".
func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

// isLocalHostName reports whether host is "localhost" or a name under it,
// which resolvers map to the loopback interface.
func isLocalHostName(host string) bool {
	return host == "localhost" || strings.HasSuffix(host, ".localhost")
}

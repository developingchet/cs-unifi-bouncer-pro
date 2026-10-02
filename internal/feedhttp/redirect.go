// Package feedhttp holds the HTTP policy shared by the bouncer's feed
// fetchers (blocklists and the Cloudflare IP list).
package feedhttp

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
)

const maxFeedRedirects = 3

// CheckRedirect limits where a feed may redirect the fetcher. Feeds are
// commonly served through a redirect (release assets, CDNs), so redirects are
// followed, but a compromised or hijacked feed host must not be able to point
// the bouncer at internal services or downgrade HTTPS. A feed configured with
// a private address or name directly is still allowed, and so is a redirect
// that stays on the same scheme, host and port; only a redirect to a different
// internal host is refused.
//
// This rejects literal addresses and local host names up front. A name that
// resolves to an internal address is refused when the connection is made, by
// the transport NewClient installs.
func CheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxFeedRedirects {
		return fmt.Errorf("stopped after %d redirects", maxFeedRedirects)
	}
	if via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
		return errors.New("refusing redirect from https to " + req.URL.Scheme)
	}
	if !sameOrigin(via[0].URL, req.URL) {
		host := normalizeHost(req.URL.Hostname())
		if addr, err := netip.ParseAddr(host); err == nil && IsInternalAddr(addr) {
			return fmt.Errorf("refusing redirect to internal address %s", addr)
		}
		if isLocalHostName(host) {
			return errors.New("refusing redirect to localhost")
		}
	}
	// The query string of a feed URL may carry a token; the next host has no
	// business seeing it in a Referer. Authorization and cookies are already
	// dropped by net/http when a redirect leaves the original domain.
	req.Header.Del("Referer")
	return nil
}

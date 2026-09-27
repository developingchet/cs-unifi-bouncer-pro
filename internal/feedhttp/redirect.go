// Package feedhttp holds the HTTP policy shared by the bouncer's feed
// fetchers (blocklists and the Cloudflare IP list).
package feedhttp

import (
	"errors"
	"fmt"
	"net"
	"net/http"
)

const maxFeedRedirects = 3

// CheckRedirect limits where a feed may redirect the fetcher. Feeds are
// commonly served through a redirect (release assets, CDNs), so redirects are
// followed, but a compromised or hijacked feed host must not be able to point
// the bouncer at internal services or downgrade HTTPS. A feed configured with
// a private address directly is still allowed; only a redirect to one is not.
func CheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxFeedRedirects {
		return fmt.Errorf("stopped after %d redirects", maxFeedRedirects)
	}
	if via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
		return errors.New("refusing redirect from https to " + req.URL.Scheme)
	}
	if ip := net.ParseIP(req.URL.Hostname()); ip != nil && isInternalIP(ip) {
		return fmt.Errorf("refusing redirect to internal address %s", ip)
	}
	if req.URL.Hostname() == "localhost" {
		return errors.New("refusing redirect to localhost")
	}
	return nil
}

func isInternalIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

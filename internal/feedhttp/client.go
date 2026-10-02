package feedhttp

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// NewClient returns the HTTP client feed fetchers use. A request the caller
// makes directly goes through the standard transport, so a feed hosted on a
// private address keeps working, and so does a redirect that stays on the
// same scheme, host and port. A request created by a redirect to a different
// host is dialled through a transport that refuses internal addresses, which
// covers host names that resolve to them: CheckRedirect only sees the name.
func NewClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: CheckRedirect,
		Transport:     newRedirectGuardTransport(),
	}
}

// redirectGuardTransport sends redirect follow-ups through a transport that
// validates every address it connects to.
type redirectGuardTransport struct {
	direct  *http.Transport
	guarded *http.Transport
}

func newRedirectGuardTransport() *redirectGuardTransport {
	direct := http.DefaultTransport.(*http.Transport).Clone()
	guarded := direct.Clone()
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   refuseInternalDial,
	}
	guarded.DialContext = dialer.DialContext
	return &redirectGuardTransport{direct: direct, guarded: guarded}
}

// RoundTrip implements http.RoundTripper. net/http sets Request.Response only
// on requests it builds to follow a redirect.
func (t *redirectGuardTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Response == nil || sameOrigin(originalRequest(req).URL, req.URL) || t.viaProxy(req) {
		return t.direct.RoundTrip(req)
	}
	return t.guarded.RoundTrip(req)
}

// viaProxy reports whether req leaves through a configured proxy. The proxy
// resolves the target name, so the address dialled here is the proxy's and
// says nothing about where the request ends up.
func (t *redirectGuardTransport) viaProxy(req *http.Request) bool {
	if t.direct.Proxy == nil {
		return false
	}
	proxyURL, err := t.direct.Proxy(req)
	return err == nil && proxyURL != nil
}

// refuseInternalDial is a net.Dialer Control hook. It runs once per resolved
// address, immediately before the connection is made, so a name cannot pass
// an earlier check and then resolve to a different address.
func refuseInternalDial(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("parse dial address %q: %w", address, err)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("parse dial address %q: %w", address, err)
	}
	if IsInternalAddr(addr) {
		return fmt.Errorf("refusing to connect to internal address %s", addr.Unmap())
	}
	return nil
}

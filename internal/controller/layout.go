package controller

import (
	"context"
	"fmt"
	"net/http"
)

// apiLayout describes where the Network application's endpoints live.
// UniFi OS consoles (UDM, UCG, Cloud Key Gen2+, UniFi OS Server) put the
// Network API behind /proxy/network and authenticate at /api/auth/login.
// A standalone Network Application (self-hosted, typically port 8443) serves
// the same API from the root and authenticates at /api/login.
type apiLayout struct {
	name          string
	networkPrefix string
	loginPath     string
}

var (
	layoutUniFiOS    = apiLayout{name: "unifi-os", networkPrefix: "/proxy/network", loginPath: "/api/auth/login"}
	layoutStandalone = apiLayout{name: "standalone", networkPrefix: "", loginPath: "/api/login"}
)

// detectLayout probes the controller root. UniFi OS serves its console at /
// with 200; a standalone Network Application redirects / to /manage. Any other
// outcome keeps the UniFi OS layout, and a failed probe is returned so the
// caller can report an unreachable controller instead of a misleading login error.
func detectLayout(ctx context.Context, client *http.Client, baseURL string) (apiLayout, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/", nil)
	if err != nil {
		return layoutUniFiOS, fmt.Errorf("build layout probe: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return layoutUniFiOS, fmt.Errorf("probe controller at %s: %w", baseURL, err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= http.StatusMultipleChoices && resp.StatusCode < http.StatusBadRequest {
		return layoutStandalone, nil
	}
	return layoutUniFiOS, nil
}

// networkURL joins the base URL, the layout's Network API prefix, and path.
func (c *unifiClient) networkURL(format string, args ...any) string {
	return c.cfg.BaseURL + c.layout.networkPrefix + fmt.Sprintf(format, args...)
}

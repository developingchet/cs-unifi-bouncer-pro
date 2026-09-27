package controller

import (
	"context"
	"encoding/json"
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
// with 200; a standalone Network Application redirects / to /manage. A 404 or
// 5xx means the controller is still starting (a standalone controller answers
// 404 until its web application is deployed), so it is returned as an error
// rather than guessed. A failed probe is also returned so the caller can report
// an unreachable controller instead of a misleading login error.
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
	switch {
	case resp.StatusCode >= http.StatusMultipleChoices && resp.StatusCode < http.StatusBadRequest:
		return layoutStandalone, nil
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode >= http.StatusInternalServerError:
		return layoutUniFiOS, fmt.Errorf("controller at %s is not ready (GET / returned HTTP %d)", baseURL, resp.StatusCode)
	}
	return layoutUniFiOS, nil
}

// classicErrorMsg returns meta.msg from a classic API error body
// ({"meta":{"rc":"error","msg":"api.err.X"}}), or "" if absent.
func classicErrorMsg(body []byte) string {
	var envelope struct {
		Meta struct {
			Msg string `json:"msg"`
		} `json:"meta"`
	}
	if json.Unmarshal(body, &envelope) != nil {
		return ""
	}
	return envelope.Meta.Msg
}

// classicErrorArg returns meta.args from a classic API error body when it is
// a single string, or "". FirewallGroupInvalidArgs puts the rejected member
// there, e.g. {"meta":{"rc":"error","args":"203.0.113.9/32",...}}.
func classicErrorArg(body []byte) string {
	var envelope struct {
		Meta struct {
			Args json.RawMessage `json:"args"`
		} `json:"meta"`
	}
	if json.Unmarshal(body, &envelope) != nil {
		return ""
	}
	var arg string
	if json.Unmarshal(envelope.Meta.Args, &arg) != nil {
		return ""
	}
	return arg
}

// networkURL joins the base URL, the layout's Network API prefix, and path.
func (c *unifiClient) networkURL(format string, args ...any) string {
	return c.cfg.BaseURL + c.layout.networkPrefix + fmt.Sprintf(format, args...)
}

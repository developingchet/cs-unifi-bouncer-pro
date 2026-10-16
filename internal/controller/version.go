package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// zoneOnlyMajor is the first UniFi Network release that runs every site on
// the zone-based firewall. Network 11 migrates each site to it on upgrade and
// no longer applies legacy WAN_IN/WANv6_IN rules.
const zoneOnlyMajor = 11

// NetworkVersion is a parsed UniFi Network application version such as
// "10.6.106".
type NetworkVersion struct {
	Major, Minor, Patch int
	Raw                 string
}

// ParseNetworkVersion parses the version string the controller reports. Only
// the major number is required; a missing minor or patch reads as 0 and any
// suffix after the numbers (a build tag) is ignored.
func ParseNetworkVersion(s string) (NetworkVersion, error) {
	raw := strings.TrimSpace(s)
	parts := strings.SplitN(strings.TrimPrefix(raw, "v"), ".", 3)
	nums := [3]int{}
	for i, part := range parts {
		digits := part
		if end := strings.IndexFunc(part, func(r rune) bool { return r < '0' || r > '9' }); end >= 0 {
			digits = part[:end]
		}
		n, err := strconv.Atoi(digits)
		if err != nil {
			if i == 0 {
				return NetworkVersion{}, fmt.Errorf("parse UniFi Network version %q: no major version", s)
			}
			break
		}
		nums[i] = n
		if len(digits) < len(part) {
			break
		}
	}
	return NetworkVersion{Major: nums[0], Minor: nums[1], Patch: nums[2], Raw: raw}, nil
}

// ZoneOnly reports whether this release enforces only the zone-based
// firewall, so legacy rules would be accepted but never applied.
func (v NetworkVersion) ZoneOnly() bool {
	return v.Major >= zoneOnlyMajor
}

func (v NetworkVersion) String() string {
	return v.Raw
}

// applicationVersion reads the Network application version. An API key reads
// the integration API's info endpoint; a session reads the classic sysinfo of
// site, which reports the controller's version whichever site is asked.
func applicationVersion(ctx context.Context, c *unifiClient, site string) (string, error) {
	if c.cfg.APIKey != "" {
		return integrationVersion(ctx, c)
	}
	return sysinfoVersion(ctx, c, site)
}

func integrationVersion(ctx context.Context, c *unifiClient) (string, error) {
	var info struct {
		ApplicationVersion string `json:"applicationVersion"`
	}
	if err := getJSON(ctx, c, c.networkURL("/integration/v1/info"), "info", &info); err != nil {
		return "", fmt.Errorf("read UniFi Network version: %w", err)
	}
	if info.ApplicationVersion == "" {
		return "", errors.New("read UniFi Network version: integration info has no applicationVersion")
	}
	return info.ApplicationVersion, nil
}

func sysinfoVersion(ctx context.Context, c *unifiClient, site string) (string, error) {
	if err := requireSegment("site", site); err != nil {
		return "", err
	}
	var sysinfo struct {
		Data []struct {
			Version string `json:"version"`
		} `json:"data"`
	}
	if err := getJSON(ctx, c, c.networkURL("/api/s/%s/stat/sysinfo", site), "sysinfo", &sysinfo); err != nil {
		return "", fmt.Errorf("read UniFi Network version: %w", err)
	}
	if len(sysinfo.Data) == 0 || sysinfo.Data[0].Version == "" {
		return "", errors.New("read UniFi Network version: sysinfo has no version")
	}
	return sysinfo.Data[0].Version, nil
}

// getJSON decodes the JSON body of a GET into out, logging in again once on 401.
func getJSON(ctx context.Context, c *unifiClient, url, endpoint string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	return c.withReauth(ctx, func() error {
		resp, err := c.apiDo(ctx, req, endpoint)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBodyBytes)).Decode(out); err != nil {
			return fmt.Errorf("decode %s: %w", endpoint, err)
		}
		return nil
	})
}

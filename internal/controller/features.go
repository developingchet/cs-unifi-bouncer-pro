package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
)

// featureFlags maps known feature names to API detection logic.
// When FIREWALL_MODE=auto, EnsureInfrastructure calls HasFeature.
const (
	FeatureZoneBasedFirewall = "ZONE_BASED_FIREWALL"
)

// hasFeature detects whether the controller supports a named feature.
// Results are cached per (site, feature) to avoid repeated API calls.
func hasFeature(ctx context.Context, c *unifiClient, site, feature string) (bool, error) {
	c.cacheMu.RLock()
	if siteCache, ok := c.featureCache[site]; ok {
		if val, cached := siteCache[feature]; cached {
			c.cacheMu.RUnlock()
			return val, nil
		}
	}
	c.cacheMu.RUnlock()

	var result bool
	var err error

	switch feature {
	case FeatureZoneBasedFirewall:
		result, err = detectZoneFirewall(ctx, c, site)
	default:
		return false, fmt.Errorf("unknown feature: %s", feature)
	}

	if err != nil {
		return false, err
	}

	c.cacheMu.Lock()
	if c.featureCache[site] == nil {
		c.featureCache[site] = make(map[string]bool)
	}
	c.featureCache[site][feature] = result
	c.cacheMu.Unlock()

	return result, nil
}

// detectZoneFirewall reports whether site enforces the zone-based firewall.
// Zone mode is driven through the integration v1 API, which only accepts API
// keys, so a session login is checked against the classic zone list instead.
func detectZoneFirewall(ctx context.Context, c *unifiClient, site string) (bool, error) {
	if c.cfg.APIKey == "" {
		return detectZoneFirewallWithSession(ctx, c, site)
	}
	siteID, err := getSiteID(ctx, c, site)
	if err != nil {
		var notFound *ErrNotFound
		if errors.As(err, &notFound) {
			return false, nil
		}
		return false, fmt.Errorf("resolve integration site %s: %w", site, err)
	}

	endpointURL := c.networkURL("/integration/v1/sites/%s/firewall/zones?limit=1", siteID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpointURL, nil)
	if err != nil {
		return false, err
	}

	var supported bool
	callErr := c.withReauth(ctx, func() error {
		resp, err := c.apiDo(ctx, req, "feature/zone-detect")
		if err != nil {
			if _, notFound := err.(*ErrNotFound); notFound {
				supported = false
				return nil
			}
			return err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
		if err != nil {
			return fmt.Errorf("read zone probe: %w", err)
		}
		// An HTML page means the path fell through to the web UI.
		if trimmed := bytes.TrimSpace(body); len(trimmed) > 0 && trimmed[0] == '<' {
			supported = false
			return nil
		}
		var page apiV1Page
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("decode zone probe: %w", err)
		}
		// Zone-based sites always carry the built-in zones; a controller
		// without a gateway answers with an empty list.
		supported = page.TotalCount > 0 || len(page.Data) > 0
		return nil
	})
	return supported, callErr
}

// detectZoneFirewallWithSession uses the session-accessible zone list. No
// zones means legacy WAN_IN rules are enforced. Zones mean the site is
// zone-based, which this bouncer can only manage through an API key.
func detectZoneFirewallWithSession(ctx context.Context, c *unifiClient, site string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.networkURL("/v2/api/site/%s/firewall/zone", site), nil)
	if err != nil {
		return false, err
	}
	var zones []json.RawMessage
	callErr := c.withReauth(ctx, func() error {
		resp, err := c.apiDo(ctx, req, "feature/zone-detect-session")
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBodyBytes)).Decode(&zones); err != nil {
			return fmt.Errorf("decode zone list: %w", err)
		}
		return nil
	})
	var notFound *ErrNotFound
	if errors.As(callErr, &notFound) {
		return false, nil // controller predates zone-based firewall
	}
	if callErr != nil {
		return false, callErr
	}
	if len(zones) > 0 {
		return false, fmt.Errorf("site %s uses the zone-based firewall, which requires UNIFI_API_KEY "+
			"(integration API); set UNIFI_API_KEY, or FIREWALL_MODE=legacy if legacy rules are still enforced", site)
	}
	return false, nil
}

// --- API helpers for legacy envelope responses ------------------------------

type apiResponse struct {
	Data []json.RawMessage `json:"data"`
	Meta struct {
		RC  string `json:"rc"`
		Msg string `json:"msg"`
	} `json:"meta"`
}

func (c *unifiClient) groupEndpoint(site string) string {
	return c.networkURL("/api/s/%s/rest/firewallgroup", site)
}

func (c *unifiClient) ruleEndpoint(site string) string {
	return c.networkURL("/api/s/%s/rest/firewallrule", site)
}

// --- Zone ID Resolution (integration v1) ------------------------------------

// getZoneID resolves a zone identifier (name or UUID) for a given site.
// If zoneName is already a standard UUID or MongoDB ObjectID, it is used directly.
// Otherwise the integration v1 firewall-zones API is consulted.
func getZoneID(ctx context.Context, c *unifiClient, site, zoneName string) (string, error) {
	c.cacheMu.RLock()
	if zoneMap, ok := c.zoneIDCache[site]; ok {
		if id, found := zoneMap[zoneName]; found {
			c.cacheMu.RUnlock()
			return id, nil
		}
	}
	c.cacheMu.RUnlock()

	// Fast path: pass through if it already looks like a UUID or ObjectID.
	if isZoneIDPassthrough(zoneName) {
		c.cacheMu.Lock()
		if c.zoneIDCache[site] == nil {
			c.zoneIDCache[site] = make(map[string]string)
		}
		c.zoneIDCache[site][zoneName] = zoneName
		c.cacheMu.Unlock()
		return zoneName, nil
	}

	// Resolve site name → UUID for integration v1 lookup.
	siteID, err := getSiteID(ctx, c, site)
	if err != nil {
		return "", fmt.Errorf("resolve site UUID for zone lookup: %w", err)
	}

	// Fetch all zones from integration v1 and populate cache.
	zones, err := listFirewallZones(ctx, c, siteID)
	if err != nil {
		return "", fmt.Errorf("list firewall zones for site %q: %w", site, err)
	}

	c.cacheMu.Lock()
	if c.zoneIDCache[site] == nil {
		c.zoneIDCache[site] = make(map[string]string)
	}
	for _, z := range zones {
		c.zoneIDCache[site][z.Name] = z.ID
		c.zoneIDCache[site][z.ID] = z.ID // also cache UUID→UUID for future fast-paths
	}
	resolved := c.zoneIDCache[site][zoneName] // read while holding lock
	c.cacheMu.Unlock()

	if resolved != "" {
		return resolved, nil
	}

	// Build list of available zone names for the error message.
	available := make([]string, 0, len(zones))
	for _, z := range zones {
		available = append(available, z.Name)
	}
	sort.Strings(available)

	// Case-insensitive "did you mean?" suggestion.
	suggestion := ""
	for _, name := range available {
		if strings.EqualFold(name, zoneName) {
			suggestion = fmt.Sprintf(" Did you mean %q (check capitalisation)?", name)
			break
		}
	}

	return "", fmt.Errorf(
		"zone %q not found on this controller.%s "+
			"Available zones: [%s]. "+
			"Zone names are case-sensitive — use exact names as shown in the UniFi UI, "+
			"or provide zone UUIDs directly (e.g. ZONE_PAIRS=<src-uuid>-><dst-uuid>)",
		zoneName, suggestion, strings.Join(available, ", "),
	)
}

// isZoneIDPassthrough returns true if s is a MongoDB ObjectID (24 hex chars)
// or a standard UUID (8-4-4-4-12 hex), either of which can be used directly.
func isZoneIDPassthrough(s string) bool {
	return isMongoObjectID(s) || isStandardUUID(s)
}

// isStandardUUID checks if a string is a standard UUID (8-4-4-4-12 format).
func isStandardUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !isHexDigit(c) {
				return false
			}
		}
	}
	return true
}

// isMongoObjectID checks if a string is a 24-char hex MongoDB ObjectID.
func isMongoObjectID(s string) bool {
	if len(s) != 24 {
		return false
	}
	for _, c := range s {
		if !isHexDigit(c) {
			return false
		}
	}
	return true
}

func isHexDigit(c rune) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

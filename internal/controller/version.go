package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
)

// featureFlags maps known feature names to API detection logic.
// When FIREWALL_MODE=auto, EnsureInfrastructure calls HasFeature.
const (
	FeatureZoneBasedFirewall = "ZONE_BASED_FIREWALL"
)

// --- UniFi Network API path helpers -----------------------------------------

const (
	pathNetworkAPI = "/proxy/network/api/s/%s/rest/"
	pathLogin      = "/api/auth/login"
	pathSelf       = "/api/self"
)

// featureCacheMu protects the per-client feature cache.
var featureCacheMu sync.RWMutex

// hasFeature detects whether the controller supports a named feature.
// Results are cached per (site, feature) to avoid repeated API calls.
func hasFeature(ctx context.Context, c *unifiClient, site, feature string) (bool, error) {
	featureCacheMu.RLock()
	if siteCache, ok := c.featureCache[site]; ok {
		if val, cached := siteCache[feature]; cached {
			featureCacheMu.RUnlock()
			return val, nil
		}
	}
	featureCacheMu.RUnlock()

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

	featureCacheMu.Lock()
	if c.featureCache[site] == nil {
		c.featureCache[site] = make(map[string]bool)
	}
	c.featureCache[site][feature] = result
	featureCacheMu.Unlock()

	return result, nil
}

// detectZoneFirewall probes the integration v1 firewall zones endpoint.
// Returns false if the site UUID cannot be resolved or the endpoint is unavailable.
func detectZoneFirewall(ctx context.Context, c *unifiClient, site string) (bool, error) {
	siteID, err := getSiteID(ctx, c, site)
	if err != nil {
		// Cannot resolve site UUID — integration v1 not available; fall back to legacy.
		return false, nil
	}

	endpointURL := fmt.Sprintf("%s/proxy/network/integration/v1/sites/%s/firewall/zones?limit=1",
		c.cfg.BaseURL, siteID)
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
		// Peek at first byte — HTML responses (proxy fallback) start with '<'
		buf := make([]byte, 1)
		if n, _ := resp.Body.Read(buf); n > 0 && buf[0] == '<' {
			supported = false
			return nil
		}
		supported = resp.StatusCode == http.StatusOK
		return nil
	})
	return supported, callErr
}

// --- API helpers for legacy envelope responses ------------------------------

type apiResponse struct {
	Data []json.RawMessage `json:"data"`
	Meta struct {
		RC  string `json:"rc"`
		Msg string `json:"msg"`
	} `json:"meta"`
}

func groupEndpoint(base, site string) string {
	return fmt.Sprintf("%s/proxy/network/api/s/%s/rest/firewallgroup", base, site)
}

func ruleEndpoint(base, site string) string {
	return fmt.Sprintf("%s/proxy/network/api/s/%s/rest/firewallrule", base, site)
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
	return "", fmt.Errorf(
		"zone %q not found on this controller (checked %d zones). "+
			"Zone names are case-sensitive. "+
			"Use ZONE_PAIRS=<src>-><dst> with exact zone names as shown in the UniFi UI, "+
			"or provide zone UUIDs directly (e.g. ZONE_PAIRS=<src-uuid>-><dst-uuid>).",
		zoneName, len(zones),
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
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
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
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

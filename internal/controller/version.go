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

// detectZoneFirewall probes the proxy v2 zone policy endpoint.
// Returns false if the endpoint returns HTML (endpoint doesn't exist).
func detectZoneFirewall(ctx context.Context, c *unifiClient, site string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, proxyPolicyEndpoint(c.cfg.BaseURL, site), nil)
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
		// Peek at first byte — HTML responses start with '<'
		buf := make([]byte, 1)
		if n, _ := resp.Body.Read(buf); n > 0 && buf[0] == '<' {
			supported = false
			return nil
		}
		supported = true
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

func zoneEndpoint(base, site string) string {
	return fmt.Sprintf("%s/proxy/network/api/s/%s/rest/firewallzone", base, site)
}

// Proxy v2 API endpoints (site name, not UUID).
// These match the UDM Pro Max firmware 10.1.85 proxy API.

func proxyPolicyEndpoint(base, site string) string {
	return fmt.Sprintf("%s/proxy/network/v2/api/site/%s/firewall-policies", base, site)
}

func proxyPolicyReorderEndpoint(base, site string) string {
	return fmt.Sprintf("%s/proxy/network/v2/api/site/%s/firewall-policies/batch-reorder", base, site)
}

// selfSitesEndpoint is still used for site UUID resolution.
func selfSitesEndpoint(base string) string {
	return fmt.Sprintf("%s/proxy/network/api/self/sites", base)
}

// --- Zone Policy Reordering (proxy v2 API) ---------------------------------

// reorderZonePolicies reorders zone policies via the proxy v2 API.
// The site parameter is a site name (not a UUID).
func reorderZonePolicies(ctx context.Context, c *unifiClient, site string, req ZonePolicyReorderRequest) error {
	payload := map[string]interface{}{
		"source_zone_id":      req.SourceZoneID,
		"destination_zone_id": req.DestinationZoneID,
		"before_policy_ids":   req.BeforeSystemDefinedIDs,
	}
	url := proxyPolicyReorderEndpoint(c.cfg.BaseURL, site)
	return doPUT(ctx, c, url, "reorder-policies", payload)
}

// --- Zone ID Resolution (proxy v2 API) -------------------------------------

// getZoneID resolves a zone identifier for a given site key.
// For UDM Pro Max firmware 10.x, zone names cannot be resolved automatically
// since there's no zone list API. Zone IDs are MongoDB ObjectIDs (24 hex chars).
// If zoneName is already a 24-char hex ObjectID, it is used directly.
// Otherwise, returns an error telling the user to use zone UUIDs directly.
func getZoneID(ctx context.Context, c *unifiClient, site, zoneName string) (string, error) {
	c.cacheMu.RLock()
	if zoneMap, ok := c.zoneIDCache[site]; ok {
		if id, found := zoneMap[zoneName]; found {
			c.cacheMu.RUnlock()
			return id, nil
		}
	}
	c.cacheMu.RUnlock()

	// If zoneName is already a 24-char hex ObjectID, use it directly
	if isMongoObjectID(zoneName) {
		c.cacheMu.Lock()
		if c.zoneIDCache[site] == nil {
			c.zoneIDCache[site] = make(map[string]string)
		}
		c.zoneIDCache[site][zoneName] = zoneName
		c.cacheMu.Unlock()
		return zoneName, nil
	}

	// No zone list API available on UDM Pro Max 10.x — return clear error
	return "", fmt.Errorf(
		"zone %q cannot be resolved: no zone list API available on this controller. "+
			"Set ZONE_PAIRS to use zone UUIDs directly, e.g. ZONE_PAIRS=%s->%s. "+
			"Find zone UUIDs in: GET /proxy/network/v2/api/site/default/firewall-policies (source.zone_id / destination.zone_id fields)",
		zoneName, zoneName, zoneName,
	)
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

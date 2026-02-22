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

// detectZoneFirewall probes the official v1 zone policy endpoint.
func detectZoneFirewall(ctx context.Context, c *unifiClient, site string) (bool, error) {
	siteID, err := getSiteID(ctx, c, site)
	if err != nil {
		return false, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v1PolicyEndpoint(c.cfg.BaseURL, siteID)+"?limit=1", nil)
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
		_ = resp.Body.Close()
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

// v1 API endpoints (require siteID UUID, not site name).

func v1SitesEndpoint(base string) string {
	return fmt.Sprintf("%s/v1/sites", base)
}

func selfSitesEndpoint(base string) string {
	return fmt.Sprintf("%s/proxy/network/api/self/sites", base)
}

func v1PolicyEndpoint(base, siteID string) string {
	return fmt.Sprintf("%s/v1/sites/%s/firewall/policies", base, siteID)
}

func v1PolicyOrderingEndpoint(base, siteID string) string {
	return fmt.Sprintf("%s/v1/sites/%s/firewall/policies/ordering", base, siteID)
}

func v1TMLEndpoint(base, siteID string) string {
	return fmt.Sprintf("%s/v1/sites/%s/traffic-matching-lists", base, siteID)
}

func v1ZoneEndpoint(base, siteID string) string {
	return fmt.Sprintf("%s/v1/sites/%s/firewall/zones", base, siteID)
}

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
// All API paths are constructed here. To adapt for a future API restructure,
// update these helpers. To add a new feature:
//  1. Add a const Feature... = "FEATURE_NAME" below
//  2. Add a newFeatureEndpoint(base, site) function here
//  3. Add a detectNewFeature(ctx, c, site) probe function here
//  4. Wire it into the hasFeature() switch
//  5. Add CRUD helpers in api.go

// Common path segments used across multiple endpoint builders.
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

// detectZoneFirewall probes the zone-policy endpoint; a 200 means the feature exists.
func detectZoneFirewall(ctx context.Context, c *unifiClient, site string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, zoneEndpoint(c.cfg.BaseURL, site), nil)
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

		var body struct {
			Data []json.RawMessage `json:"data"`
		}
		if decErr := json.NewDecoder(resp.Body).Decode(&body); decErr != nil {
			// Endpoint exists but response is unexpected — assume supported
			supported = true
			return nil
		}
		supported = true
		return nil
	})
	return supported, callErr
}

// --- API helpers for firewall groups ----------------------------------------

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

func zonePolicyEndpoint(base, site string) string {
	return fmt.Sprintf("%s/proxy/network/api/s/%s/rest/firewall-policy", base, site)
}

func zoneEndpoint(base, site string) string {
	return fmt.Sprintf("%s/proxy/network/api/s/%s/rest/firewallzone", base, site)
}

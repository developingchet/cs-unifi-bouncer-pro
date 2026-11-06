package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

// getSiteID resolves a site name to its integration v1 UUID. The name is
// normally the site's internalReference; an ID or display name also resolves.
// Results are cached on the client under the name that was asked for.
func getSiteID(ctx context.Context, c *unifiClient, siteName string) (string, error) {
	if siteName == "" {
		return "", errors.New("site name is empty")
	}
	c.cacheMu.RLock()
	if id, ok := c.siteIDCache[siteName]; ok {
		c.cacheMu.RUnlock()
		return id, nil
	}
	c.cacheMu.RUnlock()

	sites, err := listSitesV1(ctx, c)
	if err != nil {
		return "", err
	}
	id, err := matchSite(sites, siteName)
	if err != nil {
		return "", err
	}
	c.cacheMu.Lock()
	c.siteIDCache[siteName] = id
	c.cacheMu.Unlock()
	return id, nil
}

// Every controller holds at least one site, so an empty site list is a
// controller that is starting or briefly failing to answer; Network 11 can
// return one between good answers. The listing is retried a few times
// before the empty answer is believed.
const emptySiteListAttempts = 3

var emptySiteListRetryDelay = time.Second

func listSitesV1(ctx context.Context, c *unifiClient) ([]apiSiteV1, error) {
	endpointURL := c.networkURL("/integration/v1/sites")
	for attempt := 1; ; attempt++ {
		data, err := listAllV1Pages(ctx, c, endpointURL, "list-sites")
		if err != nil {
			return nil, fmt.Errorf("fetch integration v1 sites: %w", err)
		}
		sites := make([]apiSiteV1, 0, len(data))
		for _, raw := range data {
			var s apiSiteV1
			if err := json.Unmarshal(raw, &s); err != nil || s.ID == "" {
				continue
			}
			sites = append(sites, s)
		}
		if len(sites) > 0 || attempt == emptySiteListAttempts {
			return sites, nil
		}
		c.log.Warn().Int("attempt", attempt).Msg("controller listed no sites; retrying")
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(emptySiteListRetryDelay):
		}
	}
}

// matchSite picks the site that name refers to. The three identifiers share
// one namespace as far as callers are concerned, but one site's display name
// can equal another site's internalReference, so they are tried in order of
// stability: internalReference, then ID, then display name. A level that
// matches more than one site is an error rather than a guess.
func matchSite(sites []apiSiteV1, name string) (string, error) {
	levels := []struct {
		label string
		field func(apiSiteV1) string
	}{
		{"internalReference", func(s apiSiteV1) string { return s.InternalReference }},
		{"ID", func(s apiSiteV1) string { return s.ID }},
		{"name", func(s apiSiteV1) string { return s.Name }},
	}
	for _, level := range levels {
		var ids []string
		for _, s := range sites {
			if level.field(s) == name && !slices.Contains(ids, s.ID) {
				ids = append(ids, s.ID)
			}
		}
		switch len(ids) {
		case 0:
		case 1:
			return ids[0], nil
		default:
			return "", fmt.Errorf("site %q is ambiguous: %d sites share that %s", name, len(ids), level.label)
		}
	}
	return "", fmt.Errorf("site %q not found in integration v1 sites list", name)
}

// discoverSites returns the short site names (internalReference) visible to
// the configured credentials. Session logins cannot read integration v1, so
// they use the classic site list, whose name field holds the same value.
func discoverSites(ctx context.Context, c *unifiClient) ([]string, error) {
	if c.cfg.APIKey == "" {
		return discoverSitesWithSession(ctx, c)
	}
	endpointURL := c.networkURL("/integration/v1/sites")
	data, err := listAllV1Pages(ctx, c, endpointURL, "list-sites")
	if err != nil {
		return nil, fmt.Errorf("fetch integration v1 sites: %w", err)
	}
	var sites []string
	for _, raw := range data {
		var s apiSiteV1
		if err := json.Unmarshal(raw, &s); err != nil {
			continue
		}
		if s.InternalReference != "" {
			sites = append(sites, s.InternalReference)
		}
	}
	return sites, nil
}

func discoverSitesWithSession(ctx context.Context, c *unifiClient) ([]string, error) {
	data, err := doGET(ctx, c, c.networkURL("/api/self/sites"), "list-sites")
	if err != nil {
		return nil, fmt.Errorf("fetch sites: %w", err)
	}
	var sites []string
	for _, raw := range data {
		var s struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(raw, &s); err != nil {
			continue
		}
		if s.Name != "" {
			sites = append(sites, s.Name)
		}
	}
	return sites, nil
}

// --- Firewall Zones (integration v1) ----------------------------------------

// listFirewallZones fetches all zones from the integration v1 API.
// siteID must be the site UUID (from getSiteID), not the site name.
func listFirewallZones(ctx context.Context, c *unifiClient, siteID string) ([]Zone, error) {
	if err := requireSegment("site ID", siteID); err != nil {
		return nil, err
	}
	endpointURL := c.networkURL("/integration/v1/sites/%s/firewall/zones", siteID)
	data, err := listAllV1Pages(ctx, c, endpointURL, "list-zones")
	if err != nil {
		return nil, err
	}
	zones := make([]Zone, 0, len(data))
	for _, raw := range data {
		var z apiFirewallZoneV1
		if err := json.Unmarshal(raw, &z); err != nil {
			continue
		}
		zones = append(zones, Zone{ID: z.ID, Name: z.Name, NetworkIDs: z.NetworkIDs, Origin: z.Metadata.Origin})
	}
	return zones, nil
}

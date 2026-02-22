package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// --- Wire types (JSON mapping to UniFi API responses) -----------------------

type apiGroup struct {
	ID           string   `json:"_id,omitempty"`
	Name         string   `json:"name"`
	GroupType    string   `json:"group_type"`
	GroupMembers []string `json:"group_members"`
}

type apiRule struct {
	ID                  string   `json:"_id,omitempty"`
	Name                string   `json:"name"`
	Enabled             bool     `json:"enabled"`
	RuleIndex           int      `json:"rule_index"`
	Action              string   `json:"action"`
	Ruleset             string   `json:"ruleset"`
	Description         string   `json:"description"`
	Logging             bool     `json:"logging"`
	Protocol            string   `json:"protocol"`
	SrcFirewallGroupIDs []string `json:"src_firewallgroup_ids"`
}

type apiPolicySource struct {
	ZoneID             string `json:"zone_id"`
	IPGroupID          string `json:"ip_group_id,omitempty"`
	MatchingTarget     string `json:"matching_target,omitempty"`      // "ANY" or "IP"
	MatchingTargetType string `json:"matching_target_type,omitempty"` // "ANY" or "OBJECT"
	MatchOppositeIPs   bool   `json:"match_opposite_ips"`
}

type apiPolicyDestination struct {
	ZoneID         string `json:"zone_id"`
	MatchingTarget string `json:"matching_target,omitempty"` // "ANY"
}

type apiPolicy struct {
	ID          string               `json:"_id,omitempty"`
	Name        string               `json:"name,omitempty"`
	Enabled     bool                 `json:"enabled"`
	Action      string               `json:"action,omitempty"`
	Description string               `json:"description,omitempty"`
	IPVersion   string               `json:"ip_version,omitempty"`
	Source      apiPolicySource      `json:"source"`
	Destination apiPolicyDestination `json:"destination"`
	Predefined  bool                 `json:"predefined,omitempty"`
}

type apiZone struct {
	ID   string `json:"_id"`
	Name string `json:"name"`
}

// v1 API wire types

type apiSelfSite struct {
	ID   string `json:"_id"`
	Name string `json:"name"`
}

type apiV1ListResponse struct {
	Offset     int               `json:"offset"`
	Limit      int               `json:"limit"`
	Count      int               `json:"count"`
	TotalCount int               `json:"totalCount"`
	Data       []json.RawMessage `json:"data"`
}

type apiTrafficMatchingListItem struct {
	Value string `json:"value"`
}

type apiTrafficMatchingList struct {
	ID    string                       `json:"id,omitempty"`
	Type  string                       `json:"type"`
	Name  string                       `json:"name"`
	Items []apiTrafficMatchingListItem `json:"items"`
}

type apiV1TrafficFilter struct {
	IPGroupIDs []string `json:"ipGroupIds,omitempty"`
}

type apiV1PolicySource struct {
	ZoneID        string             `json:"zoneId"`
	TrafficFilter apiV1TrafficFilter `json:"trafficFilter"`
}

type apiV1PolicyDestination struct {
	ZoneID        string             `json:"zoneId"`
	TrafficFilter apiV1TrafficFilter `json:"trafficFilter"`
}

type apiV1PolicyAction struct {
	Type string `json:"type"`
}

type apiV1IPProtocolScope struct {
	IPVersion string `json:"ipVersion"`
}

type apiV1Policy struct {
	ID                    string                 `json:"id,omitempty"`
	Name                  string                 `json:"name,omitempty"`
	Description           string                 `json:"description,omitempty"`
	Enabled               bool                   `json:"enabled"`
	Action                apiV1PolicyAction      `json:"action"`
	Source                apiV1PolicySource      `json:"source"`
	Destination           apiV1PolicyDestination `json:"destination"`
	IPProtocolScope       apiV1IPProtocolScope   `json:"ipProtocolScope"`
	ConnectionStateFilter []string               `json:"connectionStateFilter,omitempty"`
	LoggingEnabled        bool                   `json:"loggingEnabled"`
	SystemDefined         bool                   `json:"systemDefined,omitempty"`
}

type apiV1Zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// --- Generic HTTP helpers ---------------------------------------------------

func doGET(ctx context.Context, c *unifiClient, url, endpoint string) ([]json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	var result []json.RawMessage
	return result, c.withReauth(ctx, func() error {
		resp, err := c.apiDo(ctx, req, endpoint)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		var body apiResponse
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
		result = body.Data
		return nil
	})
}

func doGETv1Page(ctx context.Context, c *unifiClient, rawURL, endpoint string) (apiV1ListResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return apiV1ListResponse{}, err
	}

	var page apiV1ListResponse
	err = c.withReauth(ctx, func() error {
		resp, err := c.apiDo(ctx, req, endpoint)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
		return nil
	})
	return page, err
}

func listAllV1Pages(ctx context.Context, c *unifiClient, endpointURL, metricEndpoint string) ([]json.RawMessage, error) {
	const pageLimit = 200

	base, err := url.Parse(endpointURL)
	if err != nil {
		return nil, fmt.Errorf("parse endpoint URL: %w", err)
	}

	offset := 0
	all := make([]json.RawMessage, 0)
	for {
		pageURL := *base
		query := pageURL.Query()
		query.Set("offset", fmt.Sprintf("%d", offset))
		query.Set("limit", fmt.Sprintf("%d", pageLimit))
		pageURL.RawQuery = query.Encode()

		page, err := doGETv1Page(ctx, c, pageURL.String(), metricEndpoint)
		if err != nil {
			return nil, err
		}

		all = append(all, page.Data...)
		count := page.Count
		if count == 0 {
			count = len(page.Data)
		}

		// totalCount is authoritative when present; count/len(data) are fallback guards.
		if page.TotalCount > 0 && offset+count >= page.TotalCount {
			break
		}
		if count == 0 || len(page.Data) == 0 {
			break
		}

		offset += count
	}

	return all, nil
}

func doPOST(ctx context.Context, c *unifiClient, url, endpoint string, payload interface{}) (json.RawMessage, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	var result json.RawMessage
	return result, c.withReauth(ctx, func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.apiDo(ctx, req, endpoint)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		var body apiResponse
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
		if len(body.Data) > 0 {
			result = body.Data[0]
		}
		return nil
	})
}

func doGETv2(ctx context.Context, c *unifiClient, url, endpoint string) ([]json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	var result []json.RawMessage
	return result, c.withReauth(ctx, func() error {
		resp, err := c.apiDo(ctx, req, endpoint)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
		return nil
	})
}

func doPOSTv2(ctx context.Context, c *unifiClient, url, endpoint string, payload interface{}) (json.RawMessage, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	var result json.RawMessage
	return result, c.withReauth(ctx, func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.apiDo(ctx, req, endpoint)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
		return nil
	})
}

func doPUT(ctx context.Context, c *unifiClient, url, endpoint string, payload interface{}) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return c.withReauth(ctx, func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(b))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.apiDo(ctx, req, endpoint)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		return nil
	})
}

func doDELETE(ctx context.Context, c *unifiClient, url, endpoint string) error {
	return c.withReauth(ctx, func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
		if err != nil {
			return err
		}
		resp, err := c.apiDo(ctx, req, endpoint)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		return nil
	})
}

// --- Firewall Groups --------------------------------------------------------

func listFirewallGroups(ctx context.Context, c *unifiClient, site string) ([]FirewallGroup, error) {
	data, err := doGET(ctx, c, groupEndpoint(c.cfg.BaseURL, site), "list-groups")
	if err != nil {
		return nil, err
	}
	groups := make([]FirewallGroup, 0, len(data))
	for _, raw := range data {
		var g apiGroup
		if err := json.Unmarshal(raw, &g); err != nil {
			continue
		}
		groups = append(groups, FirewallGroup{
			ID:           g.ID,
			Name:         g.Name,
			GroupType:    g.GroupType,
			GroupMembers: g.GroupMembers,
		})
	}
	return groups, nil
}

func createFirewallGroup(ctx context.Context, c *unifiClient, site string, g FirewallGroup) (FirewallGroup, error) {
	payload := apiGroup{
		Name:         g.Name,
		GroupType:    g.GroupType,
		GroupMembers: g.GroupMembers,
	}
	raw, err := doPOST(ctx, c, groupEndpoint(c.cfg.BaseURL, site), "create-group", payload)
	if err != nil {
		return FirewallGroup{}, err
	}
	var created apiGroup
	if err := json.Unmarshal(raw, &created); err != nil {
		return FirewallGroup{}, err
	}
	return FirewallGroup{ID: created.ID, Name: created.Name, GroupType: created.GroupType, GroupMembers: created.GroupMembers}, nil
}

func updateFirewallGroup(ctx context.Context, c *unifiClient, site string, g FirewallGroup) error {
	payload := apiGroup{
		ID:           g.ID,
		Name:         g.Name,
		GroupType:    g.GroupType,
		GroupMembers: g.GroupMembers,
	}
	url := groupEndpoint(c.cfg.BaseURL, site) + "/" + g.ID
	return doPUT(ctx, c, url, "update-group", payload)
}

func deleteFirewallGroup(ctx context.Context, c *unifiClient, site, id string) error {
	url := groupEndpoint(c.cfg.BaseURL, site) + "/" + id
	return doDELETE(ctx, c, url, "delete-group")
}

// --- Firewall Rules ---------------------------------------------------------

func listFirewallRules(ctx context.Context, c *unifiClient, site string) ([]FirewallRule, error) {
	data, err := doGET(ctx, c, ruleEndpoint(c.cfg.BaseURL, site), "list-rules")
	if err != nil {
		return nil, err
	}
	rules := make([]FirewallRule, 0, len(data))
	for _, raw := range data {
		var r apiRule
		if err := json.Unmarshal(raw, &r); err != nil {
			continue
		}
		rules = append(rules, FirewallRule{
			ID:                  r.ID,
			Name:                r.Name,
			Enabled:             r.Enabled,
			RuleIndex:           r.RuleIndex,
			Action:              r.Action,
			Ruleset:             r.Ruleset,
			Description:         r.Description,
			Logging:             r.Logging,
			Protocol:            r.Protocol,
			SrcFirewallGroupIDs: r.SrcFirewallGroupIDs,
		})
	}
	return rules, nil
}

func createFirewallRule(ctx context.Context, c *unifiClient, site string, r FirewallRule) (FirewallRule, error) {
	payload := apiRule{
		Name:                r.Name,
		Enabled:             r.Enabled,
		RuleIndex:           r.RuleIndex,
		Action:              r.Action,
		Ruleset:             r.Ruleset,
		Description:         r.Description,
		Logging:             r.Logging,
		Protocol:            r.Protocol,
		SrcFirewallGroupIDs: r.SrcFirewallGroupIDs,
	}
	raw, err := doPOST(ctx, c, ruleEndpoint(c.cfg.BaseURL, site), "create-rule", payload)
	if err != nil {
		return FirewallRule{}, err
	}
	var created apiRule
	if err := json.Unmarshal(raw, &created); err != nil {
		return FirewallRule{}, err
	}
	return FirewallRule{ID: created.ID, Name: created.Name, RuleIndex: created.RuleIndex, Action: created.Action, Ruleset: created.Ruleset}, nil
}

func updateFirewallRule(ctx context.Context, c *unifiClient, site string, r FirewallRule) error {
	payload := apiRule{
		ID:                  r.ID,
		Name:                r.Name,
		Enabled:             r.Enabled,
		RuleIndex:           r.RuleIndex,
		Action:              r.Action,
		Ruleset:             r.Ruleset,
		Description:         r.Description,
		Logging:             r.Logging,
		Protocol:            r.Protocol,
		SrcFirewallGroupIDs: r.SrcFirewallGroupIDs,
	}
	url := ruleEndpoint(c.cfg.BaseURL, site) + "/" + r.ID
	return doPUT(ctx, c, url, "update-rule", payload)
}

func deleteFirewallRule(ctx context.Context, c *unifiClient, site, id string) error {
	url := ruleEndpoint(c.cfg.BaseURL, site) + "/" + id
	return doDELETE(ctx, c, url, "delete-rule")
}

// --- Zone Policies (v1 API) -------------------------------------------------

// listZonePolicies fetches all zone policies from the v1 API.
// The siteID parameter must be a UUID (not a site name).
func listZonePolicies(ctx context.Context, c *unifiClient, siteID string) ([]ZonePolicy, error) {
	data, err := listAllV1Pages(ctx, c, v1PolicyEndpoint(c.cfg.BaseURL, siteID), "list-policies")
	if err != nil {
		return nil, err
	}
	policies := make([]ZonePolicy, 0, len(data))
	for _, raw := range data {
		var p apiV1Policy
		if err := json.Unmarshal(raw, &p); err != nil {
			continue
		}
		policies = append(policies, zonePolicyFromAPI(p))
	}
	return policies, nil
}

func zonePolicyFromAPI(p apiV1Policy) ZonePolicy {
	return ZonePolicy{
		ID:                     p.ID,
		Name:                   p.Name,
		Enabled:                p.Enabled,
		Action:                 p.Action.Type,
		Description:            p.Description,
		SrcZone:                p.Source.ZoneID,
		DstZone:                p.Destination.ZoneID,
		IPVersion:              p.IPProtocolScope.IPVersion,
		TrafficMatchingListIDs: p.Source.TrafficFilter.IPGroupIDs,
		Predefined:             p.SystemDefined,
		ConnectionStateFilter:  p.ConnectionStateFilter,
		LoggingEnabled:         p.LoggingEnabled,
	}
}

func zonePolicyPayloadFromModel(p ZonePolicy) ZonePolicyPayload {
	return ZonePolicyPayload{
		Enabled:     p.Enabled,
		Name:        p.Name,
		Description: p.Description,
		Action: ZonePolicyAction{
			Type: p.Action,
		},
		Source: ZonePolicyEndpoint{
			ZoneID: p.SrcZone,
			TrafficFilter: ZonePolicyTMFilter{
				IPGroupIDs: p.TrafficMatchingListIDs,
			},
		},
		Destination: ZonePolicyEndpoint{
			ZoneID: p.DstZone,
			// Empty trafficFilter means "match all destinations in zone".
			TrafficFilter: ZonePolicyTMFilter{},
		},
		IPProtocolScope: ZonePolicyIPScope{
			IPVersion: p.IPVersion,
		},
		ConnectionStateFilter: p.ConnectionStateFilter,
		LoggingEnabled:        p.LoggingEnabled,
	}
}

// createZonePolicy creates a new zone policy via the v1 API.
// The siteID parameter must be a UUID (not a site name).
func createZonePolicy(ctx context.Context, c *unifiClient, siteID string, p ZonePolicy) (ZonePolicy, error) {
	payload := zonePolicyPayloadFromModel(p)
	raw, err := doPOSTv2(ctx, c, v1PolicyEndpoint(c.cfg.BaseURL, siteID), "create-policy", payload)
	if err != nil {
		return ZonePolicy{}, err
	}
	var created apiV1Policy
	if err := json.Unmarshal(raw, &created); err != nil {
		return ZonePolicy{}, err
	}
	return zonePolicyFromAPI(created), nil
}

// updateZonePolicy updates an existing zone policy via the v1 API.
// The siteID parameter must be a UUID (not a site name).
func updateZonePolicy(ctx context.Context, c *unifiClient, siteID string, p ZonePolicy) error {
	payload := zonePolicyPayloadFromModel(p)
	url := v1PolicyEndpoint(c.cfg.BaseURL, siteID) + "/" + p.ID
	return doPUT(ctx, c, url, "update-policy", payload)
}

// deleteZonePolicy deletes a zone policy via the v1 API.
// The siteID parameter must be a UUID (not a site name).
func deleteZonePolicy(ctx context.Context, c *unifiClient, siteID, id string) error {
	url := v1PolicyEndpoint(c.cfg.BaseURL, siteID) + "/" + id
	return doDELETE(ctx, c, url, "delete-policy")
}

// --- Traffic Matching Lists (v1 API) -----------------------------------------

// listTrafficMatchingLists fetches all traffic matching lists from the v1 API.
// The siteID parameter must be a UUID (not a site name).
func listTrafficMatchingLists(ctx context.Context, c *unifiClient, siteID string) ([]TrafficMatchingList, error) {
	data, err := listAllV1Pages(ctx, c, v1TMLEndpoint(c.cfg.BaseURL, siteID), "list-traffic-matching-lists")
	if err != nil {
		return nil, err
	}
	lists := make([]TrafficMatchingList, 0, len(data))
	for _, raw := range data {
		var tml apiTrafficMatchingList
		if err := json.Unmarshal(raw, &tml); err != nil {
			continue
		}
		items := make([]TrafficMatchingListItem, 0, len(tml.Items))
		for _, item := range tml.Items {
			items = append(items, TrafficMatchingListItem{Value: item.Value})
		}
		lists = append(lists, TrafficMatchingList{
			ID:    tml.ID,
			Type:  tml.Type,
			Name:  tml.Name,
			Items: items,
		})
	}
	return lists, nil
}

// createTrafficMatchingList creates a new traffic matching list via the v1 API.
// The siteID parameter must be a UUID (not a site name).
func createTrafficMatchingList(ctx context.Context, c *unifiClient, siteID string, list TrafficMatchingList) (TrafficMatchingList, error) {
	items := make([]apiTrafficMatchingListItem, 0, len(list.Items))
	for _, item := range list.Items {
		items = append(items, apiTrafficMatchingListItem{Value: item.Value})
	}
	payload := apiTrafficMatchingList{
		Type:  list.Type,
		Name:  list.Name,
		Items: items,
	}
	raw, err := doPOSTv2(ctx, c, v1TMLEndpoint(c.cfg.BaseURL, siteID), "create-traffic-matching-list", payload)
	if err != nil {
		return TrafficMatchingList{}, err
	}
	var created apiTrafficMatchingList
	if err := json.Unmarshal(raw, &created); err != nil {
		return TrafficMatchingList{}, err
	}
	outItems := make([]TrafficMatchingListItem, 0, len(created.Items))
	for _, item := range created.Items {
		outItems = append(outItems, TrafficMatchingListItem{Value: item.Value})
	}
	return TrafficMatchingList{
		ID:    created.ID,
		Type:  created.Type,
		Name:  created.Name,
		Items: outItems,
	}, nil
}

// updateTrafficMatchingList updates an existing traffic matching list via the v1 API.
// The siteID parameter must be a UUID (not a site name).
func updateTrafficMatchingList(ctx context.Context, c *unifiClient, siteID string, list TrafficMatchingList) error {
	items := make([]apiTrafficMatchingListItem, 0, len(list.Items))
	for _, item := range list.Items {
		items = append(items, apiTrafficMatchingListItem{Value: item.Value})
	}
	payload := apiTrafficMatchingList{
		ID:    list.ID,
		Type:  list.Type,
		Name:  list.Name,
		Items: items,
	}
	url := v1TMLEndpoint(c.cfg.BaseURL, siteID) + "/" + list.ID
	return doPUT(ctx, c, url, "update-traffic-matching-list", payload)
}

// deleteTrafficMatchingList deletes a traffic matching list via the v1 API.
// The siteID parameter must be a UUID (not a site name).
func deleteTrafficMatchingList(ctx context.Context, c *unifiClient, siteID, id string) error {
	url := v1TMLEndpoint(c.cfg.BaseURL, siteID) + "/" + id
	return doDELETE(ctx, c, url, "delete-traffic-matching-list")
}

// --- Zones (v1 API) ----------------------------------------------------------

// listZonesV1 fetches all zones from the v1 API.
// The siteID parameter must be a UUID (not a site name).
func listZonesV1(ctx context.Context, c *unifiClient, siteID string) ([]Zone, error) {
	data, err := listAllV1Pages(ctx, c, v1ZoneEndpoint(c.cfg.BaseURL, siteID), "list-zones-v1")
	if err != nil {
		return nil, err
	}
	zones := make([]Zone, 0, len(data))
	for _, raw := range data {
		var z apiV1Zone
		if err := json.Unmarshal(raw, &z); err != nil {
			continue
		}
		zones = append(zones, Zone{ID: z.ID, Name: z.Name})
	}
	return zones, nil
}

// --- Site ID Resolution (v1 API) --------------------------------------------

// getSiteID resolves a site name to its UUID.
// Results are cached in the unifiClient to avoid repeated API calls.
func getSiteID(ctx context.Context, c *unifiClient, siteName string) (string, error) {
	c.cacheMu.RLock()
	if id, ok := c.siteIDCache[siteName]; ok {
		c.cacheMu.RUnlock()
		return id, nil
	}
	c.cacheMu.RUnlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, selfSitesEndpoint(c.cfg.BaseURL), nil)
	if err != nil {
		return "", err
	}

	var body apiResponse
	err = c.withReauth(ctx, func() error {
		resp, err := c.apiDo(ctx, req, "get-site-id")
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("fetch sites: %w", err)
	}

	for _, raw := range body.Data {
		var site apiSelfSite
		if err := json.Unmarshal(raw, &site); err != nil {
			continue
		}
		if site.Name == siteName || site.ID == siteName {
			c.cacheMu.Lock()
			c.siteIDCache[site.Name] = site.ID
			c.siteIDCache[siteName] = site.ID
			c.cacheMu.Unlock()
			return site.ID, nil
		}
	}

	return "", fmt.Errorf("site %q not found in self/sites response", siteName)
}

// getZoneID resolves a zone name to its UUID for a given site UUID.
// Results are cached per site ID.
func getZoneID(ctx context.Context, c *unifiClient, siteID, zoneName string) (string, error) {
	c.cacheMu.RLock()
	if zoneMap, ok := c.zoneIDCache[siteID]; ok {
		if id, found := zoneMap[zoneName]; found {
			c.cacheMu.RUnlock()
			return id, nil
		}
	}
	c.cacheMu.RUnlock()

	zones, err := listZonesV1(ctx, c, siteID)
	if err != nil {
		return "", err
	}

	zoneMap := make(map[string]string, len(zones)*2)
	for _, z := range zones {
		zoneMap[z.Name] = z.ID
		zoneMap[z.ID] = z.ID
	}

	c.cacheMu.Lock()
	c.zoneIDCache[siteID] = zoneMap
	c.cacheMu.Unlock()

	if id, found := zoneMap[zoneName]; found {
		return id, nil
	}

	return "", fmt.Errorf("zone %q not found for site %s", zoneName, siteID)
}

// reorderZonePolicies reorders zone policies via the v1 API.
// The siteID parameter must be a UUID (not a site name).
func reorderZonePolicies(ctx context.Context, c *unifiClient, siteID string, req ZonePolicyReorderRequest) error {
	orderURL, err := url.Parse(v1PolicyOrderingEndpoint(c.cfg.BaseURL, siteID))
	if err != nil {
		return err
	}
	query := orderURL.Query()
	query.Set("sourceFirewallZoneId", req.SourceZoneID)
	query.Set("destinationFirewallZoneId", req.DestinationZoneID)
	orderURL.RawQuery = query.Encode()

	payload := map[string]interface{}{
		"orderedFirewallPolicyIds": map[string][]string{
			"beforeSystemDefined": req.BeforeSystemDefinedIDs,
			"afterSystemDefined":  req.AfterSystemDefinedIDs,
		},
	}

	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	return c.withReauth(ctx, func() error {
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPut, orderURL.String(), bytes.NewReader(b))
		if err != nil {
			return err
		}
		httpReq.Header.Set("Content-Type", "application/json")
		resp, err := c.apiDo(ctx, httpReq, "reorder-policies")
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		return nil
	})
}

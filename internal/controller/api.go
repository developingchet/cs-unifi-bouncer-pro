package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// --- Legacy REST wire types -------------------------------------------------

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

// --- Integration v1 wire types ----------------------------------------------

// apiSiteV1 is returned by GET /proxy/network/integration/v1/sites.
type apiSiteV1 struct {
	ID                string `json:"id"`
	InternalReference string `json:"internalReference"`
	Name              string `json:"name"`
}

// apiV1Page is the pagination envelope for all integration v1 list endpoints.
type apiV1Page struct {
	Offset     int               `json:"offset"`
	Limit      int               `json:"limit"`
	Count      int               `json:"count"`
	TotalCount int               `json:"totalCount"`
	Data       []json.RawMessage `json:"data"`
}

// apiFirewallZoneV1 is the zone wire type for the integration v1 API.
// The id field is a UUID (not a MongoDB ObjectID).
type apiFirewallZoneV1 struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Metadata struct {
		Origin string `json:"origin"`
	} `json:"metadata"`
}

// apiTMLItemV1 is one entry in an integration v1 TML.
type apiTMLItemV1 struct {
	Type  string      `json:"type"`   // "IP_ADDRESS", "SUBNET", "PORT_NUMBER"
	Value interface{} `json:"value"`  // string for IPs/subnets, int for ports
}

// apiTMLV1 is the integration v1 Traffic Matching List wire type.
type apiTMLV1 struct {
	ID    string         `json:"id,omitempty"`
	Type  string         `json:"type"`  // "IPV4_ADDRESSES", "IPV6_ADDRESSES", "PORTS"
	Name  string         `json:"name"`
	Items []apiTMLItemV1 `json:"items"`
}

// apiTMLV1Update is the wire type for TML PUT requests (excludes id field per UniFi API).
type apiTMLV1Update struct {
	Type  string         `json:"type"`  // "IPV4_ADDRESSES", "IPV6_ADDRESSES", "PORTS"
	Name  string         `json:"name"`
	Items []apiTMLItemV1 `json:"items"`
}

// Integration v1 zone policy wire types.
type apiV1PolicyAction struct {
	Type               string `json:"type"`                         // "BLOCK", "ALLOW", "REJECT"
	AllowReturnTraffic bool   `json:"allowReturnTraffic,omitempty"` // only for ALLOW
}

type apiV1IPAddressFilter struct {
	Type                  string `json:"type"`                            // "TRAFFIC_MATCHING_LIST"
	MatchOpposite         bool   `json:"matchOpposite"`
	TrafficMatchingListID string `json:"trafficMatchingListId,omitempty"`
}

// apiV1PortFilter references a PORTS TML for source or destination port filtering.
// It is always nested inside trafficFilter — the UniFi POST endpoint rejects
// portFilter at the top level of source or destination.
type apiV1PortFilter struct {
	Type                  string `json:"type"`                            // "TRAFFIC_MATCHING_LIST"
	MatchOpposite         bool   `json:"matchOpposite"`
	TrafficMatchingListID string `json:"trafficMatchingListId,omitempty"`
}

type apiV1TrafficFilter struct {
	Type            string                `json:"type,omitempty"` // "IP_ADDRESS"
	IPAddressFilter *apiV1IPAddressFilter `json:"ipAddressFilter,omitempty"`
	PortFilter      *apiV1PortFilter      `json:"portFilter,omitempty"` // nested here, not at source/dst level
}

type apiV1PolicySrc struct {
	ZoneID        string              `json:"zoneId"`
	TrafficFilter *apiV1TrafficFilter `json:"trafficFilter,omitempty"`
}

type apiV1PolicyDst struct {
	ZoneID        string              `json:"zoneId"`
	TrafficFilter *apiV1TrafficFilter `json:"trafficFilter,omitempty"`
}

type apiV1IPScope struct {
	IPVersion string `json:"ipVersion"` // "IPV4", "IPV6", "IPV4_AND_IPV6"
}

type apiV1Policy struct {
	ID                    string            `json:"id,omitempty"`
	Enabled               bool              `json:"enabled"`
	Name                  string            `json:"name"`
	Description           string            `json:"description,omitempty"`
	Index                 int               `json:"index,omitempty"`
	Action                apiV1PolicyAction `json:"action"`
	Source                apiV1PolicySrc    `json:"source"`
	Destination           apiV1PolicyDst    `json:"destination"`
	IPProtocolScope       apiV1IPScope      `json:"ipProtocolScope"`
	ConnectionStateFilter []string          `json:"connectionStateFilter,omitempty"`
	LoggingEnabled        bool              `json:"loggingEnabled"`
}

// apiV1PolicyUpdateSrc is the source struct for PUT requests.
// portFilter is intentionally absent: the UniFi PUT endpoint rejects
// '$.source.portFilter' as an unknown property. portFilter can only be
// set at creation time (POST). When portFilter needs to change, the
// caller must delete the existing policy and recreate it.
type apiV1PolicyUpdateSrc struct {
	ZoneID        string              `json:"zoneId"`
	TrafficFilter *apiV1TrafficFilter `json:"trafficFilter,omitempty"`
}

// apiV1PolicyUpdateDst is the destination struct for PUT requests.
// portFilter is intentionally absent for the same reason as apiV1PolicyUpdateSrc.
type apiV1PolicyUpdateDst struct {
	ZoneID string `json:"zoneId"`
}

// apiV1PolicyUpdate is used for PUT requests — omits both '$.id' and portFilter,
// both of which the UniFi PUT endpoint rejects.
type apiV1PolicyUpdate struct {
	Enabled               bool                 `json:"enabled"`
	Name                  string               `json:"name"`
	Description           string               `json:"description,omitempty"`
	Index                 int                  `json:"index,omitempty"`
	Action                apiV1PolicyAction    `json:"action"`
	Source                apiV1PolicyUpdateSrc `json:"source"`
	Destination           apiV1PolicyUpdateDst `json:"destination"`
	IPProtocolScope       apiV1IPScope         `json:"ipProtocolScope"`
	ConnectionStateFilter []string             `json:"connectionStateFilter,omitempty"`
	LoggingEnabled        bool                 `json:"loggingEnabled"`
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

func doPOST(ctx context.Context, c *unifiClient, url, endpoint string, payload interface{}) (json.RawMessage, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	var result json.RawMessage
	err = c.withReauth(ctx, func() error {
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
	return result, err
}

func doPOSTv2(ctx context.Context, c *unifiClient, url, endpoint string, payload interface{}) (json.RawMessage, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	var result json.RawMessage
	err = c.withReauth(ctx, func() error {
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
	return result, err
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

// --- Firewall Groups (legacy REST) ------------------------------------------

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
		groups = append(groups, FirewallGroup(g))
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
	return FirewallGroup(created), nil
}

func updateFirewallGroup(ctx context.Context, c *unifiClient, site string, g FirewallGroup) error {
	payload := apiGroup(g)
	u := groupEndpoint(c.cfg.BaseURL, site) + "/" + g.ID
	return doPUT(ctx, c, u, "update-group", payload)
}

func deleteFirewallGroup(ctx context.Context, c *unifiClient, site, id string) error {
	u := groupEndpoint(c.cfg.BaseURL, site) + "/" + id
	return ignoreNotFound(doDELETE(ctx, c, u, "delete-group"))
}

// --- Firewall Rules (legacy REST) -------------------------------------------

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
		rules = append(rules, FirewallRule(r))
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
	return FirewallRule{
		ID:        created.ID,
		Name:      created.Name,
		RuleIndex: created.RuleIndex,
		Action:    created.Action,
		Ruleset:   created.Ruleset,
	}, nil
}

func updateFirewallRule(ctx context.Context, c *unifiClient, site string, r FirewallRule) error {
	payload := apiRule(r)
	u := ruleEndpoint(c.cfg.BaseURL, site) + "/" + r.ID
	return doPUT(ctx, c, u, "update-rule", payload)
}

func deleteFirewallRule(ctx context.Context, c *unifiClient, site, id string) error {
	u := ruleEndpoint(c.cfg.BaseURL, site) + "/" + id
	return ignoreNotFound(doDELETE(ctx, c, u, "delete-rule"))
}

// --- Integration v1 helpers -------------------------------------------------

// listAllV1Pages fetches all pages from an integration v1 paginated endpoint.
func listAllV1Pages(ctx context.Context, c *unifiClient, endpointURL, metricEndpoint string) ([]json.RawMessage, error) {
	const pageLimit = 200
	base, err := url.Parse(endpointURL)
	if err != nil {
		return nil, fmt.Errorf("parse URL %q: %w", endpointURL, err)
	}
	var all []json.RawMessage
	offset := 0
	for {
		u := *base
		q := u.Query()
		q.Set("offset", strconv.Itoa(offset))
		q.Set("limit", strconv.Itoa(pageLimit))
		u.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
		var page apiV1Page
		err = c.withReauth(ctx, func() error {
			resp, err := c.apiDo(ctx, req, metricEndpoint)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			return json.NewDecoder(resp.Body).Decode(&page)
		})
		if err != nil {
			return nil, err
		}
		all = append(all, page.Data...)
		if len(page.Data) == 0 || (page.TotalCount > 0 && offset+page.Count >= page.TotalCount) {
			break
		}
		offset += page.Count
	}
	return all, nil
}

// getSiteID resolves a site internalReference to its integration v1 UUID.
// Results are cached on the client.
func getSiteID(ctx context.Context, c *unifiClient, siteName string) (string, error) {
	c.cacheMu.RLock()
	if id, ok := c.siteIDCache[siteName]; ok {
		c.cacheMu.RUnlock()
		return id, nil
	}
	c.cacheMu.RUnlock()

	endpointURL := c.cfg.BaseURL + "/proxy/network/integration/v1/sites"
	data, err := listAllV1Pages(ctx, c, endpointURL, "list-sites")
	if err != nil {
		return "", fmt.Errorf("fetch integration v1 sites: %w", err)
	}

	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	for _, raw := range data {
		var s apiSiteV1
		if err := json.Unmarshal(raw, &s); err != nil {
			continue
		}
		// Cache by both internalReference and display name for convenience.
		c.siteIDCache[s.InternalReference] = s.ID
		c.siteIDCache[s.Name] = s.ID
		c.siteIDCache[s.ID] = s.ID // also cache UUID → UUID
	}
	if id, ok := c.siteIDCache[siteName]; ok {
		return id, nil
	}
	return "", fmt.Errorf("site %q not found in integration v1 sites list", siteName)
}

// --- Firewall Zones (integration v1) ----------------------------------------

// listFirewallZones fetches all zones from the integration v1 API.
// siteID must be the site UUID (from getSiteID), not the site name.
func listFirewallZones(ctx context.Context, c *unifiClient, siteID string) ([]Zone, error) {
	endpointURL := fmt.Sprintf("%s/proxy/network/integration/v1/sites/%s/firewall/zones",
		c.cfg.BaseURL, siteID)
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
		zones = append(zones, Zone{ID: z.ID, Name: z.Name, Origin: z.Metadata.Origin})
	}
	return zones, nil
}

// --- Traffic Matching Lists (integration v1) ---------------------------------

func listTMLs(ctx context.Context, c *unifiClient, siteID string) ([]TrafficMatchingList, error) {
	endpointURL := fmt.Sprintf("%s/proxy/network/integration/v1/sites/%s/traffic-matching-lists",
		c.cfg.BaseURL, siteID)
	data, err := listAllV1Pages(ctx, c, endpointURL, "list-tmls")
	if err != nil {
		return nil, err
	}
	out := make([]TrafficMatchingList, 0, len(data))
	for _, raw := range data {
		var t apiTMLV1
		if err := json.Unmarshal(raw, &t); err != nil {
			continue
		}
		out = append(out, tmlFromWire(t))
	}
	return out, nil
}

func createTML(ctx context.Context, c *unifiClient, siteID string, list TrafficMatchingList) (TrafficMatchingList, error) {
	endpointURL := fmt.Sprintf("%s/proxy/network/integration/v1/sites/%s/traffic-matching-lists",
		c.cfg.BaseURL, siteID)
	raw, err := doPOSTv2(ctx, c, endpointURL, "create-tml", tmlToWire(list))
	if err != nil {
		return TrafficMatchingList{}, err
	}
	var created apiTMLV1
	if err := json.Unmarshal(raw, &created); err != nil {
		return TrafficMatchingList{}, fmt.Errorf("decode created TML: %w", err)
	}
	return tmlFromWire(created), nil
}

func updateTML(ctx context.Context, c *unifiClient, siteID string, list TrafficMatchingList) error {
	endpointURL := fmt.Sprintf("%s/proxy/network/integration/v1/sites/%s/traffic-matching-lists/%s",
		c.cfg.BaseURL, siteID, list.ID)
	return doPUT(ctx, c, endpointURL, "update-tml", tmlToWireUpdate(list))
}

func deleteTML(ctx context.Context, c *unifiClient, siteID, id string) error {
	endpointURL := fmt.Sprintf("%s/proxy/network/integration/v1/sites/%s/traffic-matching-lists/%s",
		c.cfg.BaseURL, siteID, id)
	return ignoreNotFound(doDELETE(ctx, c, endpointURL, "delete-tml"))
}

func tmlItemToWire(item TrafficMatchingListItem) apiTMLItemV1 {
	t := item.Type
	if t == "" {
		// Fallback to inference if Type is not set
		t = "IP_ADDRESS"
		if strings.Contains(item.Value, "/") {
			t = "SUBNET"
		}
	}
	if t == "PORT_NUMBER" {
		if n, err := strconv.Atoi(item.Value); err == nil {
			return apiTMLItemV1{Type: t, Value: n}
		}
	}
	return apiTMLItemV1{Type: t, Value: item.Value}
}

func tmlToWire(list TrafficMatchingList) apiTMLV1 {
	items := make([]apiTMLItemV1, 0, len(list.Items))
	for _, item := range list.Items {
		items = append(items, tmlItemToWire(item))
	}
	tmlType := list.Type
	if tmlType == "" {
		if list.GroupType == "ipv6-address-group" {
			tmlType = "IPV6_ADDRESSES"
		} else {
			tmlType = "IPV4_ADDRESSES"
		}
	}
	return apiTMLV1{ID: list.ID, Type: tmlType, Name: list.Name, Items: items}
}

func tmlToWireUpdate(list TrafficMatchingList) apiTMLV1Update {
	items := make([]apiTMLItemV1, 0, len(list.Items))
	for _, item := range list.Items {
		items = append(items, tmlItemToWire(item))
	}
	tmlType := list.Type
	if tmlType == "" {
		if list.GroupType == "ipv6-address-group" {
			tmlType = "IPV6_ADDRESSES"
		} else {
			tmlType = "IPV4_ADDRESSES"
		}
	}
	return apiTMLV1Update{Type: tmlType, Name: list.Name, Items: items}
}

func tmlFromWire(t apiTMLV1) TrafficMatchingList {
	items := make([]TrafficMatchingListItem, 0, len(t.Items))
	for _, item := range t.Items {
		val := fmt.Sprintf("%v", item.Value)
		items = append(items, TrafficMatchingListItem{Type: item.Type, Value: val})
	}
	return TrafficMatchingList{ID: t.ID, Type: t.Type, Name: t.Name, Items: items}
}

// --- Zone Policies (integration v1) -----------------------------------------

func listZonePoliciesV1(ctx context.Context, c *unifiClient, siteID string) ([]ZonePolicy, error) {
	endpointURL := fmt.Sprintf("%s/proxy/network/integration/v1/sites/%s/firewall/policies",
		c.cfg.BaseURL, siteID)
	data, err := listAllV1Pages(ctx, c, endpointURL, "list-policies")
	if err != nil {
		return nil, err
	}
	out := make([]ZonePolicy, 0, len(data))
	for _, raw := range data {
		var p apiV1Policy
		if err := json.Unmarshal(raw, &p); err != nil {
			continue
		}
		out = append(out, v1PolicyToModel(p))
	}
	return out, nil
}

func createZonePolicyV1(ctx context.Context, c *unifiClient, siteID string, policy ZonePolicy) (ZonePolicy, error) {
	endpointURL := fmt.Sprintf("%s/proxy/network/integration/v1/sites/%s/firewall/policies",
		c.cfg.BaseURL, siteID)
	raw, err := doPOSTv2(ctx, c, endpointURL, "create-policy", modelToV1Policy(policy))
	if err != nil {
		return ZonePolicy{}, err
	}
	var created apiV1Policy
	if err := json.Unmarshal(raw, &created); err != nil {
		return ZonePolicy{}, fmt.Errorf("decode created policy: %w", err)
	}
	return v1PolicyToModel(created), nil
}

func updateZonePolicyV1(ctx context.Context, c *unifiClient, siteID string, policy ZonePolicy) error {
	endpointURL := fmt.Sprintf("%s/proxy/network/integration/v1/sites/%s/firewall/policies/%s",
		c.cfg.BaseURL, siteID, policy.ID)
	return doPUT(ctx, c, endpointURL, "update-policy", modelToV1PolicyUpdate(policy))
}

func deleteZonePolicyV1(ctx context.Context, c *unifiClient, siteID, id string) error {
	endpointURL := fmt.Sprintf("%s/proxy/network/integration/v1/sites/%s/firewall/policies/%s",
		c.cfg.BaseURL, siteID, id)
	return ignoreNotFound(doDELETE(ctx, c, endpointURL, "delete-policy"))
}

func v1PolicyToModel(p apiV1Policy) ZonePolicy {
	var tmlIDs []string
	if p.Source.TrafficFilter != nil &&
		p.Source.TrafficFilter.IPAddressFilter != nil &&
		p.Source.TrafficFilter.IPAddressFilter.TrafficMatchingListID != "" {
		tmlIDs = []string{p.Source.TrafficFilter.IPAddressFilter.TrafficMatchingListID}
	}
	var srcPortTMLID, dstPortTMLID string
	if p.Source.TrafficFilter != nil && p.Source.TrafficFilter.PortFilter != nil {
		srcPortTMLID = p.Source.TrafficFilter.PortFilter.TrafficMatchingListID
	}
	if p.Destination.TrafficFilter != nil && p.Destination.TrafficFilter.PortFilter != nil {
		dstPortTMLID = p.Destination.TrafficFilter.PortFilter.TrafficMatchingListID
	}
	ipVersion := p.IPProtocolScope.IPVersion
	if ipVersion == "IPV4_AND_IPV6" {
		ipVersion = "BOTH"
	}
	return ZonePolicy{
		ID:                     p.ID,
		Name:                   p.Name,
		Description:            p.Description,
		Enabled:                p.Enabled,
		Action:                 p.Action.Type,
		AllowReturnTraffic:     p.Action.AllowReturnTraffic,
		SrcZone:                p.Source.ZoneID,
		DstZone:                p.Destination.ZoneID,
		IPVersion:              ipVersion,
		ConnectionStateFilter:  p.ConnectionStateFilter,
		LoggingEnabled:         p.LoggingEnabled,
		TrafficMatchingListIDs: tmlIDs,
		SrcPortTMLID:           srcPortTMLID,
		DstPortTMLID:           dstPortTMLID,
	}
}

func buildPortFilter(tmlID string) *apiV1PortFilter {
	if tmlID == "" {
		return nil
	}
	return &apiV1PortFilter{
		Type:                  "TRAFFIC_MATCHING_LIST",
		MatchOpposite:         false,
		TrafficMatchingListID: tmlID,
	}
}

// buildMatchAllIPFilter returns an ipAddressFilter that matches any IP address.
// matchOpposite:true with no TML ID means "invert an empty set = match all".
// Used when a trafficFilter is needed solely to carry a portFilter with no
// IP restriction on the destination side.
func buildMatchAllIPFilter() *apiV1IPAddressFilter {
	return &apiV1IPAddressFilter{
		Type:          "TRAFFIC_MATCHING_LIST",
		MatchOpposite: true,
		// TrafficMatchingListID intentionally empty: complement of empty set = match all IPs
	}
}

func modelToV1Policy(p ZonePolicy) apiV1Policy {
	src := apiV1PolicySrc{ZoneID: p.SrcZone}
	var srcTF *apiV1TrafficFilter
	if len(p.TrafficMatchingListIDs) > 0 && p.TrafficMatchingListIDs[0] != "" {
		srcTF = &apiV1TrafficFilter{
			Type: "IP_ADDRESS",
			IPAddressFilter: &apiV1IPAddressFilter{
				Type:                  "TRAFFIC_MATCHING_LIST",
				MatchOpposite:         false,
				TrafficMatchingListID: p.TrafficMatchingListIDs[0],
			},
		}
	}
	if p.SrcPortTMLID != "" {
		if srcTF == nil {
			// No IP TML on source — use match-all IP filter so portFilter has a valid companion.
			srcTF = &apiV1TrafficFilter{Type: "IP_ADDRESS", IPAddressFilter: buildMatchAllIPFilter()}
		}
		srcTF.PortFilter = buildPortFilter(p.SrcPortTMLID)
	}
	src.TrafficFilter = srcTF
	dst := apiV1PolicyDst{ZoneID: p.DstZone}
	if p.DstPortTMLID != "" {
		// Destination has no IP TML — use match-all IP filter so portFilter has a valid companion.
		dst.TrafficFilter = &apiV1TrafficFilter{
			Type:            "IP_ADDRESS",
			IPAddressFilter: buildMatchAllIPFilter(),
			PortFilter:      buildPortFilter(p.DstPortTMLID),
		}
	}
	ipVersion := p.IPVersion
	switch ipVersion {
	case "BOTH":
		ipVersion = "IPV4_AND_IPV6"
	case "":
		ipVersion = "IPV4"
	}
	return apiV1Policy{
		ID:                    p.ID,
		Enabled:               p.Enabled,
		Name:                  p.Name,
		Description:           p.Description,
		Action:                apiV1PolicyAction{Type: p.Action, AllowReturnTraffic: p.AllowReturnTraffic},
		Source:                src,
		Destination:           dst,
		IPProtocolScope:       apiV1IPScope{IPVersion: ipVersion},
		ConnectionStateFilter: p.ConnectionStateFilter,
		LoggingEnabled:        p.LoggingEnabled,
	}
}

// modelToV1PolicyUpdate converts to apiV1PolicyUpdate for PUT requests.
// It omits both '$.id' and portFilter — the UniFi PUT endpoint rejects both.
// When portFilter needs to be added or changed on an existing policy, the
// caller must delete the old policy and call createZonePolicyV1 instead.
func modelToV1PolicyUpdate(p ZonePolicy) apiV1PolicyUpdate {
	src := apiV1PolicyUpdateSrc{ZoneID: p.SrcZone}
	if len(p.TrafficMatchingListIDs) > 0 && p.TrafficMatchingListIDs[0] != "" {
		src.TrafficFilter = &apiV1TrafficFilter{
			Type: "IP_ADDRESS",
			IPAddressFilter: &apiV1IPAddressFilter{
				Type:                  "TRAFFIC_MATCHING_LIST",
				MatchOpposite:         false,
				TrafficMatchingListID: p.TrafficMatchingListIDs[0],
			},
		}
	}
	dst := apiV1PolicyUpdateDst{ZoneID: p.DstZone}
	ipVersion := p.IPVersion
	switch ipVersion {
	case "BOTH":
		ipVersion = "IPV4_AND_IPV6"
	case "":
		ipVersion = "IPV4"
	}
	return apiV1PolicyUpdate{
		Enabled:               p.Enabled,
		Name:                  p.Name,
		Description:           p.Description,
		Action:                apiV1PolicyAction{Type: p.Action, AllowReturnTraffic: p.AllowReturnTraffic},
		Source:                src,
		Destination:           dst,
		IPProtocolScope:       apiV1IPScope{IPVersion: ipVersion},
		ConnectionStateFilter: p.ConnectionStateFilter,
		LoggingEnabled:        p.LoggingEnabled,
	}
}


package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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

// --- Proxy v2 API wire types for zone policies -------------------------------
// These match the live UDM Pro Max firmware 10.1.85 proxy API.

type proxyPolicy struct {
	ID                    string              `json:"_id,omitempty"`
	Name                  string              `json:"name"`
	Description           string              `json:"description,omitempty"`
	Action                string              `json:"action"`
	Enabled               bool                `json:"enabled"`
	IPVersion             string              `json:"ip_version"`
	Logging               bool                `json:"logging"`
	Protocol              string              `json:"protocol,omitempty"`
	Predefined            bool                `json:"predefined,omitempty"`
	ConnectionStateType   string              `json:"connection_state_type"`
	ConnectionStates      []string            `json:"connection_states"`
	CreateAllowRespond    bool                `json:"create_allow_respond"`
	MatchIPSec            bool                `json:"match_ip_sec"`
	MatchOppositeProtocol bool                `json:"match_opposite_protocol"`
	ICMPTypename          string              `json:"icmp_typename,omitempty"`
	ICMPv6Typename        string              `json:"icmp_v6_typename,omitempty"`
	Index                 int                 `json:"index,omitempty"`
	Schedule              proxyPolicySchedule `json:"schedule"`
	Source                proxyPolicyMatch    `json:"source"`
	Destination           proxyPolicyMatch    `json:"destination"`
}

type proxyPolicySchedule struct {
	Mode         string   `json:"mode"`
	RepeatOnDays []string `json:"repeat_on_days,omitempty"`
	TimeAllDay   bool     `json:"time_all_day,omitempty"`
}

type proxyPolicyMatch struct {
	ZoneID             string   `json:"zone_id"`
	MatchingTarget     string   `json:"matching_target"`
	MatchingTargetType string   `json:"matching_target_type,omitempty"`
	IPGroupID          string   `json:"ip_group_id,omitempty"`
	IPs                []string `json:"ips,omitempty"`
	MatchMAC           bool     `json:"match_mac,omitempty"`
	MatchOppositeIPs   bool     `json:"match_opposite_ips,omitempty"`
	MatchOppositePorts bool     `json:"match_opposite_ports,omitempty"`
	PortMatchingType   string   `json:"port_matching_type,omitempty"`
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
	return FirewallGroup{
		ID:           created.ID,
		Name:         created.Name,
		GroupType:    created.GroupType,
		GroupMembers: created.GroupMembers,
	}, nil
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
	return FirewallRule{
		ID:        created.ID,
		Name:      created.Name,
		RuleIndex: created.RuleIndex,
		Action:    created.Action,
		Ruleset:   created.Ruleset,
	}, nil
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

// --- Zone Policies (proxy v2 API) ------------------------------------------

// proxyPolicyFromModel builds a proxyPolicy from a ZonePolicy model.
func proxyPolicyFromModel(p ZonePolicy) proxyPolicy {
	connStateType := "ALL"
	connStates := []string{}
	if len(p.ConnectionStateFilter) > 0 {
		connStateType = "CUSTOM"
		connStates = p.ConnectionStateFilter
	}

	src := proxyPolicyMatch{
		ZoneID:             p.SrcZone,
		IPs:                []string{},
		MatchMAC:           false,
		MatchOppositeIPs:   false,
		MatchOppositePorts: false,
		PortMatchingType:   "ANY",
	}
	if len(p.TrafficMatchingListIDs) > 0 && p.TrafficMatchingListIDs[0] != "" {
		src.MatchingTarget = "IP"
		src.MatchingTargetType = "OBJECT"
		src.IPGroupID = p.TrafficMatchingListIDs[0]
	} else {
		src.MatchingTarget = "ANY"
	}

	dst := proxyPolicyMatch{
		ZoneID:             p.DstZone,
		MatchingTarget:     "ANY",
		MatchOppositePorts: false,
		PortMatchingType:   "ANY",
	}

	ipVersion := p.IPVersion
	if ipVersion == "" {
		ipVersion = "IPV4"
	}

	return proxyPolicy{
		Name:                  p.Name,
		Description:           p.Description,
		Action:                "BLOCK",
		Enabled:               p.Enabled,
		IPVersion:             ipVersion,
		Logging:               p.LoggingEnabled,
		Protocol:              "all",
		ConnectionStateType:   connStateType,
		ConnectionStates:      connStates,
		CreateAllowRespond:    false,
		MatchIPSec:            false,
		MatchOppositeProtocol: false,
		ICMPTypename:          "ANY",
		ICMPv6Typename:        "ANY",
		Schedule: proxyPolicySchedule{
			Mode:         "ALWAYS",
			RepeatOnDays: []string{},
			TimeAllDay:   false,
		},
		Source:      src,
		Destination: dst,
	}
}

// zonePolicyFromProxy converts a proxyPolicy to a ZonePolicy model.
func zonePolicyFromProxy(p proxyPolicy) ZonePolicy {
	return ZonePolicy{
		ID:                     p.ID,
		Name:                   p.Name,
		Enabled:                p.Enabled,
		Action:                 p.Action,
		Description:            p.Description,
		SrcZone:                p.Source.ZoneID,
		DstZone:                p.Destination.ZoneID,
		IPVersion:              p.IPVersion,
		TrafficMatchingListIDs: tmlIDsFromProxy(p.Source),
		Predefined:             p.Predefined,
		ConnectionStateFilter:  p.ConnectionStates,
		LoggingEnabled:         p.Logging,
	}
}

// tmlIDsFromProxy extracts traffic matching list IDs from the source endpoint.
func tmlIDsFromProxy(src proxyPolicyMatch) []string {
	if src.IPGroupID != "" {
		return []string{src.IPGroupID}
	}
	return nil
}

// listZonePolicies fetches all zone policies from the proxy v2 API.
// The site parameter is a site name (not a UUID).
func listZonePolicies(ctx context.Context, c *unifiClient, site string) ([]ZonePolicy, error) {
	data, err := doGETv2(ctx, c, proxyPolicyEndpoint(c.cfg.BaseURL, site), "list-policies")
	if err != nil {
		return nil, err
	}
	policies := make([]ZonePolicy, 0, len(data))
	for _, raw := range data {
		var p proxyPolicy
		if err := json.Unmarshal(raw, &p); err != nil {
			continue
		}
		policies = append(policies, zonePolicyFromProxy(p))
	}
	return policies, nil
}

// createZonePolicy creates a new zone policy via the proxy v2 API.
// The site parameter is a site name (not a UUID).
func createZonePolicy(ctx context.Context, c *unifiClient, site string, p ZonePolicy) (ZonePolicy, error) {
	payload := proxyPolicyFromModel(p)
	raw, err := doPOSTv2(ctx, c, proxyPolicyEndpoint(c.cfg.BaseURL, site), "create-policy", payload)
	if err != nil {
		return ZonePolicy{}, err
	}
	var created proxyPolicy
	if err := json.Unmarshal(raw, &created); err != nil {
		return ZonePolicy{}, fmt.Errorf("decode created policy: %w", err)
	}
	return zonePolicyFromProxy(created), nil
}

// updateZonePolicy updates an existing zone policy via the proxy v2 API.
// The site parameter is a site name (not a UUID).
func updateZonePolicy(ctx context.Context, c *unifiClient, site string, p ZonePolicy) error {
	payload := proxyPolicyFromModel(p)
	url := proxyPolicyEndpoint(c.cfg.BaseURL, site) + "/" + p.ID
	return doPUT(ctx, c, url, "update-policy", payload)
}

// deleteZonePolicy deletes a zone policy via the proxy v2 API.
// The site parameter is a site name (not a UUID).
func deleteZonePolicy(ctx context.Context, c *unifiClient, site, id string) error {
	url := proxyPolicyEndpoint(c.cfg.BaseURL, site) + "/" + id
	return doDELETE(ctx, c, url, "delete-policy")
}

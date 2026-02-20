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

type apiPolicy struct {
	ID          string     `json:"_id,omitempty"`
	Name        string     `json:"name"`
	Enabled     bool       `json:"enabled"`
	Action      string     `json:"action"`
	Description string     `json:"description"`
	SrcZone     string     `json:"src_zone"`
	DstZone     string     `json:"dst_zone"`
	IPVersion   string     `json:"ip_version"`
	MatchIPs    []apiMatch `json:"match_ips"`
	Priority    int        `json:"priority"`
}

type apiMatch struct {
	FirewallGroupID string `json:"firewall_group_id"`
	Negate          bool   `json:"negate"`
}

type apiZone struct {
	ID   string `json:"_id"`
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

// --- Zone Policies ----------------------------------------------------------

func listZonePolicies(ctx context.Context, c *unifiClient, site string) ([]ZonePolicy, error) {
	data, err := doGET(ctx, c, zonePolicyEndpoint(c.cfg.BaseURL, site), "list-policies")
	if err != nil {
		return nil, err
	}
	policies := make([]ZonePolicy, 0, len(data))
	for _, raw := range data {
		var p apiPolicy
		if err := json.Unmarshal(raw, &p); err != nil {
			continue
		}
		matchSets := make([]MatchSet, 0, len(p.MatchIPs))
		for _, m := range p.MatchIPs {
			matchSets = append(matchSets, MatchSet{FirewallGroupID: m.FirewallGroupID, Negate: m.Negate})
		}
		policies = append(policies, ZonePolicy{
			ID:          p.ID,
			Name:        p.Name,
			Enabled:     p.Enabled,
			Action:      p.Action,
			Description: p.Description,
			SrcZone:     p.SrcZone,
			DstZone:     p.DstZone,
			IPVersion:   p.IPVersion,
			MatchIPs:    matchSets,
			Priority:    p.Priority,
		})
	}
	return policies, nil
}

func createZonePolicy(ctx context.Context, c *unifiClient, site string, p ZonePolicy) (ZonePolicy, error) {
	matchIPs := make([]apiMatch, 0, len(p.MatchIPs))
	for _, m := range p.MatchIPs {
		matchIPs = append(matchIPs, apiMatch{FirewallGroupID: m.FirewallGroupID, Negate: m.Negate})
	}
	payload := apiPolicy{
		Name:        p.Name,
		Enabled:     p.Enabled,
		Action:      p.Action,
		Description: p.Description,
		SrcZone:     p.SrcZone,
		DstZone:     p.DstZone,
		IPVersion:   p.IPVersion,
		MatchIPs:    matchIPs,
		Priority:    p.Priority,
	}
	raw, err := doPOST(ctx, c, zonePolicyEndpoint(c.cfg.BaseURL, site), "create-policy", payload)
	if err != nil {
		return ZonePolicy{}, err
	}
	var created apiPolicy
	if err := json.Unmarshal(raw, &created); err != nil {
		return ZonePolicy{}, err
	}
	return ZonePolicy{ID: created.ID, Name: created.Name, SrcZone: created.SrcZone, DstZone: created.DstZone}, nil
}

func updateZonePolicy(ctx context.Context, c *unifiClient, site string, p ZonePolicy) error {
	matchIPs := make([]apiMatch, 0, len(p.MatchIPs))
	for _, m := range p.MatchIPs {
		matchIPs = append(matchIPs, apiMatch{FirewallGroupID: m.FirewallGroupID, Negate: m.Negate})
	}
	payload := apiPolicy{
		ID:          p.ID,
		Name:        p.Name,
		Enabled:     p.Enabled,
		Action:      p.Action,
		Description: p.Description,
		SrcZone:     p.SrcZone,
		DstZone:     p.DstZone,
		IPVersion:   p.IPVersion,
		MatchIPs:    matchIPs,
		Priority:    p.Priority,
	}
	url := zonePolicyEndpoint(c.cfg.BaseURL, site) + "/" + p.ID
	return doPUT(ctx, c, url, "update-policy", payload)
}

func deleteZonePolicy(ctx context.Context, c *unifiClient, site, id string) error {
	url := zonePolicyEndpoint(c.cfg.BaseURL, site) + "/" + id
	return doDELETE(ctx, c, url, "delete-policy")
}

func reorderZonePolicies(ctx context.Context, c *unifiClient, site string, orderedIDs []string) error {
	url := zonePolicyEndpoint(c.cfg.BaseURL, site) + "/reorder"
	payload := map[string]interface{}{"ids": orderedIDs}
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
		resp, err := c.apiDo(ctx, req, "reorder-policies")
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		return nil
	})
}

// --- Zones ------------------------------------------------------------------

func listZones(ctx context.Context, c *unifiClient, site string) ([]Zone, error) {
	data, err := doGET(ctx, c, zoneEndpoint(c.cfg.BaseURL, site), "list-zones")
	if err != nil {
		return nil, err
	}
	zones := make([]Zone, 0, len(data))
	for _, raw := range data {
		var z apiZone
		if err := json.Unmarshal(raw, &z); err != nil {
			continue
		}
		zones = append(zones, Zone{ID: z.ID, Name: z.Name})
	}
	return zones, nil
}

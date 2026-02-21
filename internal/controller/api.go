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

type apiPolicySource struct {
	ZoneID             string `json:"zone_id"`
	IPGroupID          string `json:"ip_group_id,omitempty"`
	MatchingTarget     string `json:"matching_target,omitempty"` // "ANY" or "IP"
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
		var matchSets []MatchSet
		if p.Source.IPGroupID != "" {
			matchSets = []MatchSet{{
				FirewallGroupID: p.Source.IPGroupID,
				Negate:          p.Source.MatchOppositeIPs,
			}}
		}
		policies = append(policies, ZonePolicy{
			ID:          p.ID,
			Name:        p.Name,
			Enabled:     p.Enabled,
			Action:      p.Action,
			Description: p.Description,
			SrcZone:     p.Source.ZoneID,
			DstZone:     p.Destination.ZoneID,
			IPVersion:   p.IPVersion,
			MatchIPs:    matchSets,
			Predefined:  p.Predefined,
		})
	}
	return policies, nil
}

func createZonePolicy(ctx context.Context, c *unifiClient, site string, p ZonePolicy) (ZonePolicy, error) {
	src := apiPolicySource{
		ZoneID: p.SrcZone,
	}
	if len(p.MatchIPs) > 0 {
		src.IPGroupID = p.MatchIPs[0].FirewallGroupID
		src.MatchOppositeIPs = p.MatchIPs[0].Negate
		if src.IPGroupID != "" {
			src.MatchingTarget = "IP"
			src.MatchingTargetType = "OBJECT"
		}
	} else {
		src.MatchingTarget = "ANY"
	}
	payload := apiPolicy{
		Name:        p.Name,
		Enabled:     p.Enabled,
		Action:      p.Action,
		Description: p.Description,
		IPVersion:   p.IPVersion,
		Source:      src,
		Destination: apiPolicyDestination{
			ZoneID:         p.DstZone,
			MatchingTarget: "ANY",
		},
	}
	raw, err := doPOST(ctx, c, zonePolicyEndpoint(c.cfg.BaseURL, site), "create-policy", payload)
	if err != nil {
		return ZonePolicy{}, err
	}
	var created apiPolicy
	if err := json.Unmarshal(raw, &created); err != nil {
		return ZonePolicy{}, err
	}
	return ZonePolicy{ID: created.ID, Name: created.Name, SrcZone: created.Source.ZoneID, DstZone: created.Destination.ZoneID}, nil
}

func updateZonePolicy(ctx context.Context, c *unifiClient, site string, p ZonePolicy) error {
	src := apiPolicySource{
		ZoneID: p.SrcZone,
	}
	if len(p.MatchIPs) > 0 {
		src.IPGroupID = p.MatchIPs[0].FirewallGroupID
		src.MatchOppositeIPs = p.MatchIPs[0].Negate
		if src.IPGroupID != "" {
			src.MatchingTarget = "IP"
			src.MatchingTargetType = "OBJECT"
		}
	} else {
		src.MatchingTarget = "ANY"
	}
	payload := apiPolicy{
		ID:          p.ID,
		Name:        p.Name,
		Enabled:     p.Enabled,
		Action:      p.Action,
		Description: p.Description,
		IPVersion:   p.IPVersion,
		Source:      src,
		Destination: apiPolicyDestination{
			ZoneID:         p.DstZone,
			MatchingTarget: "ANY",
		},
	}
	url := zonePolicyEndpoint(c.cfg.BaseURL, site) + "/" + p.ID
	return doPUT(ctx, c, url, "update-policy", payload)
}

func deleteZonePolicy(ctx context.Context, c *unifiClient, site, id string) error {
	url := zonePolicyEndpoint(c.cfg.BaseURL, site) + "/" + id
	return doDELETE(ctx, c, url, "delete-policy")
}

func reorderZonePolicies(ctx context.Context, c *unifiClient, site string, req ZonePolicyReorderRequest) error {
	url := zonePolicyEndpoint(c.cfg.BaseURL, site) + "/batch-reorder"
	payload := map[string]interface{}{
		"source_zone_id":        req.SourceZoneID,
		"destination_zone_id":   req.DestinationZoneID,
		"before_predefined_ids":  req.BeforePredefinedIDs,
		"after_predefined_ids":   req.AfterPredefinedIDs,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return c.withReauth(ctx, func() error {
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(b))
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

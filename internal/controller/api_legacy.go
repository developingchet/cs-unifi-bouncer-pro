package controller

import (
	"context"
	"encoding/json"
	"net/url"
	"slices"
)

// --- Firewall Groups (legacy REST) ------------------------------------------

func listFirewallGroups(ctx context.Context, c *unifiClient, site string) ([]FirewallGroup, error) {
	if err := requireSegment("site", site); err != nil {
		return nil, err
	}
	data, err := doGET(ctx, c, c.groupEndpoint(site), "list-groups")
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
	if err := requireSegment("site", site); err != nil {
		return FirewallGroup{}, err
	}
	payload := apiGroup{
		Name:         g.Name,
		GroupType:    g.GroupType,
		GroupMembers: g.GroupMembers,
	}
	raw, err := doPOST(ctx, c, c.groupEndpoint(site), "create-group", payload)
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
	if err := requireSegments("site", site, "firewall group ID", g.ID); err != nil {
		return err
	}
	payload := apiGroup(g)
	u := c.groupEndpoint(site) + "/" + url.PathEscape(g.ID)
	return doPUT(ctx, c, u, "update-group", payload)
}

func deleteFirewallGroup(ctx context.Context, c *unifiClient, site, id string) error {
	if err := requireSegments("site", site, "firewall group ID", id); err != nil {
		return err
	}
	u := c.groupEndpoint(site) + "/" + url.PathEscape(id)
	return confirmDeleted(doDELETE(ctx, c, u, "delete-group"), "firewall group "+id, func() (bool, error) {
		groups, err := listFirewallGroups(ctx, c, site)
		return slices.ContainsFunc(groups, func(g FirewallGroup) bool { return g.ID == id }), err
	})
}

// --- Firewall Rules (legacy REST) -------------------------------------------

func listFirewallRules(ctx context.Context, c *unifiClient, site string) ([]FirewallRule, error) {
	if err := requireSegment("site", site); err != nil {
		return nil, err
	}
	data, err := doGET(ctx, c, c.ruleEndpoint(site), "list-rules")
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
	if err := requireSegment("site", site); err != nil {
		return FirewallRule{}, err
	}
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
	raw, err := doPOST(ctx, c, c.ruleEndpoint(site), "create-rule", payload)
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
	if err := requireSegments("site", site, "firewall rule ID", r.ID); err != nil {
		return err
	}
	payload := apiRule(r)
	u := c.ruleEndpoint(site) + "/" + url.PathEscape(r.ID)
	return doPUT(ctx, c, u, "update-rule", payload)
}

func deleteFirewallRule(ctx context.Context, c *unifiClient, site, id string) error {
	if err := requireSegments("site", site, "firewall rule ID", id); err != nil {
		return err
	}
	u := c.ruleEndpoint(site) + "/" + url.PathEscape(id)
	return confirmDeleted(doDELETE(ctx, c, u, "delete-rule"), "firewall rule "+id, func() (bool, error) {
		rules, err := listFirewallRules(ctx, c, site)
		return slices.ContainsFunc(rules, func(r FirewallRule) bool { return r.ID == id }), err
	})
}

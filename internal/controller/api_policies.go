package controller

import (
	"context"
	"encoding/json"
	"fmt"
)

// --- Zone Policies (integration v1) -----------------------------------------

func listZonePoliciesV1(ctx context.Context, c *unifiClient, siteID string) ([]ZonePolicy, error) {
	if err := requireSegment("site ID", siteID); err != nil {
		return nil, err
	}
	endpointURL := c.networkURL("/integration/v1/sites/%s/firewall/policies", siteID)
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
	if err := requireSegment("site ID", siteID); err != nil {
		return ZonePolicy{}, err
	}
	endpointURL := c.networkURL("/integration/v1/sites/%s/firewall/policies", siteID)
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
	if err := requireSegments("site ID", siteID, "zone policy ID", policy.ID); err != nil {
		return err
	}
	endpointURL := c.networkURL("/integration/v1/sites/%s/firewall/policies/%s", siteID, policy.ID)
	return doPUT(ctx, c, endpointURL, "update-policy", modelToV1PolicyUpdate(policy))
}

func deleteZonePolicyV1(ctx context.Context, c *unifiClient, siteID, id string) error {
	if err := requireSegments("site ID", siteID, "zone policy ID", id); err != nil {
		return err
	}
	endpointURL := c.networkURL("/integration/v1/sites/%s/firewall/policies/%s", siteID, id)
	return confirmDeleted(doDELETE(ctx, c, endpointURL, "delete-policy"), "zone policy "+id, func() (bool, error) {
		return v1CollectionHasID(ctx, c, c.networkURL("/integration/v1/sites/%s/firewall/policies", siteID), "list-policies", id)
	})
}

func v1PolicyToModel(p apiV1Policy) ZonePolicy {
	var tmlIDs []string
	if p.Source.TrafficFilter != nil &&
		p.Source.TrafficFilter.IPAddressFilter != nil &&
		p.Source.TrafficFilter.IPAddressFilter.TrafficMatchingListID != "" {
		tmlIDs = []string{p.Source.TrafficFilter.IPAddressFilter.TrafficMatchingListID}
	}
	var srcPortTMLID, dstPortTMLID, dstIPTMLID string
	if p.Source.TrafficFilter != nil && p.Source.TrafficFilter.PortFilter != nil {
		srcPortTMLID = p.Source.TrafficFilter.PortFilter.TrafficMatchingListID
	}
	if p.Destination.TrafficFilter != nil && p.Destination.TrafficFilter.PortFilter != nil {
		dstPortTMLID = p.Destination.TrafficFilter.PortFilter.TrafficMatchingListID
	}
	if p.Destination.TrafficFilter != nil && p.Destination.TrafficFilter.IPAddressFilter != nil {
		dstIPTMLID = p.Destination.TrafficFilter.IPAddressFilter.TrafficMatchingListID
	}
	ipVersion := p.IPProtocolScope.IPVersion
	if ipVersion == "IPV4_AND_IPV6" {
		ipVersion = "BOTH"
	}
	return ZonePolicy{
		ID:                     p.ID,
		Name:                   p.Name,
		Index:                  p.Index,
		Description:            p.Description,
		Enabled:                p.Enabled,
		Action:                 p.Action.Type,
		AllowReturnTraffic:     p.Action.AllowReturnTraffic,
		SrcZone:                p.Source.ZoneID,
		DstZone:                p.Destination.ZoneID,
		IPVersion:              ipVersion,
		ConnectionStateFilter:  p.ConnectionStateFilter,
		LoggingEnabled:         p.LoggingEnabled,
		ReportFlowEnabled:      p.ReportFlowEnabled,
		TrafficMatchingListIDs: tmlIDs,
		SrcPortTMLID:           srcPortTMLID,
		DstPortTMLID:           dstPortTMLID,
		DstIPTMLID:             dstIPTMLID,
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

// normalizeIPVersion maps the model's IPVersion ("BOTH", "" or an explicit
// wire value) to the integration v1 wire value.
func normalizeIPVersion(ipVersion string) string {
	switch ipVersion {
	case "BOTH":
		return "IPV4_AND_IPV6"
	case "":
		return "IPV4"
	default:
		return ipVersion
	}
}

// buildIPAddressFilter builds a TRAFFIC_MATCHING_LIST IP address filter for
// the given TML id, or nil if no TML id is set.
func buildIPAddressFilter(tmlID string) *apiV1IPAddressFilter {
	if tmlID == "" {
		return nil
	}
	return &apiV1IPAddressFilter{
		Type:                  "TRAFFIC_MATCHING_LIST",
		MatchOpposite:         false,
		TrafficMatchingListID: tmlID,
	}
}

func modelToV1Policy(p ZonePolicy) apiV1Policy {
	src := apiV1PolicySrc{ZoneID: p.SrcZone}
	var srcTF *apiV1TrafficFilter
	if len(p.TrafficMatchingListIDs) > 0 && p.TrafficMatchingListIDs[0] != "" {
		srcTF = &apiV1TrafficFilter{
			Type:            "IP_ADDRESS",
			IPAddressFilter: buildIPAddressFilter(p.TrafficMatchingListIDs[0]),
		}
	}
	if p.SrcPortTMLID != "" {
		if srcTF == nil {
			// No IP TML on source — PORT type carries portFilter with no IP filter required.
			srcTF = &apiV1TrafficFilter{Type: "PORT"}
		}
		srcTF.PortFilter = buildPortFilter(p.SrcPortTMLID)
	}
	src.TrafficFilter = srcTF
	dst := apiV1PolicyDst{ZoneID: p.DstZone}
	var dstTF *apiV1TrafficFilter
	if p.DstIPTMLID != "" {
		dstTF = &apiV1TrafficFilter{
			Type:            "IP_ADDRESS",
			IPAddressFilter: buildIPAddressFilter(p.DstIPTMLID),
		}
	}
	if p.DstPortTMLID != "" {
		if dstTF == nil {
			dstTF = &apiV1TrafficFilter{Type: "PORT"}
		}
		dstTF.PortFilter = buildPortFilter(p.DstPortTMLID)
	}
	dst.TrafficFilter = dstTF
	return apiV1Policy{
		ID:                    p.ID,
		Enabled:               p.Enabled,
		Name:                  p.Name,
		Description:           p.Description,
		Action:                apiV1PolicyAction{Type: p.Action, AllowReturnTraffic: p.AllowReturnTraffic},
		Source:                src,
		Destination:           dst,
		IPProtocolScope:       apiV1IPScope{IPVersion: normalizeIPVersion(p.IPVersion)},
		ConnectionStateFilter: p.ConnectionStateFilter,
		LoggingEnabled:        p.LoggingEnabled,
		ReportFlowEnabled:     p.ReportFlowEnabled,
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
			Type:            "IP_ADDRESS",
			IPAddressFilter: buildIPAddressFilter(p.TrafficMatchingListIDs[0]),
		}
	}
	dst := apiV1PolicyUpdateDst{ZoneID: p.DstZone}
	return apiV1PolicyUpdate{
		Enabled:               p.Enabled,
		Name:                  p.Name,
		Description:           p.Description,
		Action:                apiV1PolicyAction{Type: p.Action, AllowReturnTraffic: p.AllowReturnTraffic},
		Source:                src,
		Destination:           dst,
		IPProtocolScope:       apiV1IPScope{IPVersion: normalizeIPVersion(p.IPVersion)},
		ConnectionStateFilter: p.ConnectionStateFilter,
		LoggingEnabled:        p.LoggingEnabled,
		ReportFlowEnabled:     p.ReportFlowEnabled,
	}
}

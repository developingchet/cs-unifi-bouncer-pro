package controller

import (
	"encoding/json"
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

// apiSiteV1 is returned by GET {network}/integration/v1/sites.
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
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	NetworkIDs []string `json:"networkIds"`
	Metadata   struct {
		Origin string `json:"origin"`
	} `json:"metadata"`
}

// apiTMLItemV1 is one entry in an integration v1 TML.
type apiTMLItemV1 struct {
	Type  string      `json:"type"`  // "IP_ADDRESS", "SUBNET", "PORT_NUMBER"
	Value interface{} `json:"value"` // string for IPs/subnets, int for ports
}

// apiTMLV1 is the integration v1 Traffic Matching List wire type.
type apiTMLV1 struct {
	ID    string         `json:"id,omitempty"`
	Type  string         `json:"type"` // "IPV4_ADDRESSES", "IPV6_ADDRESSES", "PORTS"
	Name  string         `json:"name"`
	Items []apiTMLItemV1 `json:"items"`
}

// apiTMLV1Update is the wire type for TML PUT requests (excludes id field per UniFi API).
type apiTMLV1Update struct {
	Type  string         `json:"type"` // "IPV4_ADDRESSES", "IPV6_ADDRESSES", "PORTS"
	Name  string         `json:"name"`
	Items []apiTMLItemV1 `json:"items"`
}

// Integration v1 zone policy wire types.
type apiV1PolicyAction struct {
	Type               string `json:"type"`                         // "BLOCK", "ALLOW", "REJECT"
	AllowReturnTraffic bool   `json:"allowReturnTraffic,omitempty"` // only for ALLOW
}

type apiV1IPAddressFilter struct {
	Type                  string `json:"type"` // "TRAFFIC_MATCHING_LIST"
	MatchOpposite         bool   `json:"matchOpposite"`
	TrafficMatchingListID string `json:"trafficMatchingListId,omitempty"`
}

// apiV1PortFilter references a PORTS TML for source or destination port filtering.
// It is always nested inside trafficFilter — the UniFi POST endpoint rejects
// portFilter at the top level of source or destination.
type apiV1PortFilter struct {
	Type                  string `json:"type"` // "TRAFFIC_MATCHING_LIST"
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
	Index                 *int              `json:"index,omitempty"`
	Action                apiV1PolicyAction `json:"action"`
	Source                apiV1PolicySrc    `json:"source"`
	Destination           apiV1PolicyDst    `json:"destination"`
	IPProtocolScope       apiV1IPScope      `json:"ipProtocolScope"`
	ConnectionStateFilter []string          `json:"connectionStateFilter,omitempty"`
	LoggingEnabled        bool              `json:"loggingEnabled"`
	// ReportFlowEnabled is reported from UniFi Network 11 on; when a write
	// leaves it out, the controller sets it to true.
	ReportFlowEnabled *bool `json:"reportFlowEnabled,omitempty"`
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
	ReportFlowEnabled     *bool                `json:"reportFlowEnabled,omitempty"`
}

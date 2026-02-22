package controller

import (
	"context"
	"fmt"
	"time"
)

// FirewallGroup represents a UniFi address-list group.
type FirewallGroup struct {
	ID           string
	Name         string
	GroupType    string // "address-group" or "ipv6-address-group"
	GroupMembers []string
}

// FirewallRule represents a UniFi firewall rule (legacy mode).
type FirewallRule struct {
	ID                  string
	Name                string
	Enabled             bool
	RuleIndex           int
	Action              string // "drop" or "reject"
	Ruleset             string // "WAN_IN", "WANv6_IN", etc.
	Description         string
	Logging             bool
	Protocol            string
	SrcFirewallGroupIDs []string
}

// ZonePolicy represents a UniFi zone-based firewall policy.
type ZonePolicy struct {
	ID                     string
	Name                   string
	Enabled                bool
	Action                 string // "BLOCK"
	Description            string
	SrcZone                string
	DstZone                string
	IPVersion              string   // "IPV4", "IPV6", "BOTH"
	TrafficMatchingListIDs []string // proxy API: source.ip_group_id (single ID)
	Predefined             bool     // true for built-in policies managed by UniFi
	ConnectionStateFilter  []string // e.g. ["NEW", "INVALID"]
	LoggingEnabled         bool
}

// MatchSet is deprecated; kept for backward compatibility.
// Zone mode now uses TrafficMatchingListIDs instead.
type MatchSet struct {
	FirewallGroupID string
	Negate          bool
}

// ZonePolicyReorderRequest specifies how to reorder zone policies for a specific zone pair.
type ZonePolicyReorderRequest struct {
	SourceZoneID           string
	DestinationZoneID      string
	BeforeSystemDefinedIDs []string // policy IDs evaluated before system-defined policies
	AfterSystemDefinedIDs  []string // policy IDs evaluated after system-defined policies
}

// Zone represents a UniFi network zone (topology discovery).
type Zone struct {
	ID   string
	Name string
}

// TrafficMatchingList is a v1 API Traffic Matching List (used in zone policies).
type TrafficMatchingList struct {
	ID    string                    `json:"id,omitempty"`
	Type  string                    `json:"type"` // "IPV4_ADDRESSES" or "IPV6_ADDRESSES"
	Name  string                    `json:"name"`
	Items []TrafficMatchingListItem `json:"items"`
}

// TrafficMatchingListItem represents a single IP or CIDR in a Traffic Matching List.
type TrafficMatchingListItem struct {
	Value string `json:"value"` // IP or CIDR notation
}

// ZonePolicyPayload mirrors the official v1 API payload for create/update.
type ZonePolicyPayload struct {
	Enabled               bool               `json:"enabled"`
	Name                  string             `json:"name"`
	Description           string             `json:"description,omitempty"`
	Action                ZonePolicyAction   `json:"action"`
	Source                ZonePolicyEndpoint `json:"source"`
	Destination           ZonePolicyEndpoint `json:"destination"`
	IPProtocolScope       ZonePolicyIPScope  `json:"ipProtocolScope"`
	ConnectionStateFilter []string           `json:"connectionStateFilter,omitempty"`
	LoggingEnabled        bool               `json:"loggingEnabled"`
}

type ZonePolicyAction struct {
	Type string `json:"type"` // "BLOCK" or "ALLOW"
}

type ZonePolicyEndpoint struct {
	ZoneID        string             `json:"zoneId"`
	TrafficFilter ZonePolicyTMFilter `json:"trafficFilter"`
}

type ZonePolicyTMFilter struct {
	IPGroupIDs []string `json:"ipGroupIds,omitempty"`
}

type ZonePolicyIPScope struct {
	IPVersion string `json:"ipVersion"` // "IPV4", "IPV6", or "BOTH"
}

// Controller is the UniFi API seam. All methods accept context for deadline control.
type Controller interface {
	// Firewall Groups (address lists)
	ListFirewallGroups(ctx context.Context, site string) ([]FirewallGroup, error)
	CreateFirewallGroup(ctx context.Context, site string, g FirewallGroup) (FirewallGroup, error)
	UpdateFirewallGroup(ctx context.Context, site string, g FirewallGroup) error
	DeleteFirewallGroup(ctx context.Context, site string, id string) error

	// Legacy Rules (WAN_IN / WANv6_IN)
	ListFirewallRules(ctx context.Context, site string) ([]FirewallRule, error)
	CreateFirewallRule(ctx context.Context, site string, r FirewallRule) (FirewallRule, error)
	UpdateFirewallRule(ctx context.Context, site string, r FirewallRule) error
	DeleteFirewallRule(ctx context.Context, site string, id string) error

	// Zone-Based Policies
	ListZonePolicies(ctx context.Context, site string) ([]ZonePolicy, error)
	CreateZonePolicy(ctx context.Context, site string, p ZonePolicy) (ZonePolicy, error)
	UpdateZonePolicy(ctx context.Context, site string, p ZonePolicy) error
	DeleteZonePolicy(ctx context.Context, site string, id string) error
	ReorderZonePolicies(ctx context.Context, site string, req ZonePolicyReorderRequest) error

	// Zones (read-only - topology discovery)
	ListZones(ctx context.Context, site string) ([]Zone, error)
	GetZoneID(ctx context.Context, site, zoneName string) (string, error)

	// Traffic Matching Lists (legacy v1 API compatibility)
	ListTrafficMatchingLists(ctx context.Context, site string) ([]TrafficMatchingList, error)
	CreateTrafficMatchingList(ctx context.Context, site string, list TrafficMatchingList) (TrafficMatchingList, error)
	UpdateTrafficMatchingList(ctx context.Context, site string, list TrafficMatchingList) error
	DeleteTrafficMatchingList(ctx context.Context, site string, id string) error

	// Site UUID resolution
	GetSiteID(ctx context.Context, siteName string) (string, error)

	// Feature Detection
	HasFeature(ctx context.Context, site string, feature string) (bool, error)

	// Session
	Ping(ctx context.Context) error
	Close() error
}

// --- Typed errors -----------------------------------------------------------

// ErrUnauthorized is returned on HTTP 401 responses.
type ErrUnauthorized struct {
	Msg string
}

func (e *ErrUnauthorized) Error() string {
	return fmt.Sprintf("unauthorized: %s", e.Msg)
}

// ErrNotFound is returned when a resource does not exist.
type ErrNotFound struct {
	ID string
}

func (e *ErrNotFound) Error() string {
	return fmt.Sprintf("not found: %s", e.ID)
}

// ErrRateLimit is returned when the controller signals rate limiting.
type ErrRateLimit struct {
	RetryAfter time.Duration
}

func (e *ErrRateLimit) Error() string {
	return fmt.Sprintf("rate limited (retry after %s)", e.RetryAfter)
}

// ErrConflict is returned when a create operation would cause a duplicate.
type ErrConflict struct {
	Msg string
}

func (e *ErrConflict) Error() string {
	return fmt.Sprintf("conflict: %s", e.Msg)
}

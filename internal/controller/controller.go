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

// Zone represents a UniFi network zone (topology discovery).
type Zone struct {
	ID     string
	Name   string
	Origin string // metadata.origin from integration v1 API, e.g. "USER_DEFINED"
}

// TrafficMatchingList represents an integration v1 IP/port list (zone mode).
type TrafficMatchingList struct {
	ID        string
	Type      string // "IPV4_ADDRESSES", "IPV6_ADDRESSES", "PORTS"
	Name      string
	GroupType string // legacy compat hint: "address-group", "ipv6-address-group"
	Items     []TrafficMatchingListItem
}

// TrafficMatchingListItem is one entry in a TrafficMatchingList.
type TrafficMatchingListItem struct {
	Type  string `json:"-"` // "IP_ADDRESS", "SUBNET", "PORT_NUMBER"; omitted from JSON to match wire format
	Value string
}

// ZonePolicyReorderRequest orders user-defined policies within a zone pair.
// Zone IDs must be integration v1 UUIDs.
type ZonePolicyReorderRequest struct {
	SourceZoneID           string
	DestinationZoneID      string
	BeforeSystemDefinedIDs []string
}

// Controller is the UniFi API seam. All methods accept context for deadline control.
type Controller interface {
	// Firewall Groups (address lists) — legacy mode only
	ListFirewallGroups(ctx context.Context, site string) ([]FirewallGroup, error)
	CreateFirewallGroup(ctx context.Context, site string, g FirewallGroup) (FirewallGroup, error)
	UpdateFirewallGroup(ctx context.Context, site string, g FirewallGroup) error
	DeleteFirewallGroup(ctx context.Context, site string, id string) error

	// Legacy Rules (WAN_IN / WANv6_IN) — legacy mode only
	ListFirewallRules(ctx context.Context, site string) ([]FirewallRule, error)
	CreateFirewallRule(ctx context.Context, site string, r FirewallRule) (FirewallRule, error)
	UpdateFirewallRule(ctx context.Context, site string, r FirewallRule) error
	DeleteFirewallRule(ctx context.Context, site string, id string) error

	// Zone-Based Policies — integration v1
	ListZonePolicies(ctx context.Context, site string) ([]ZonePolicy, error)
	CreateZonePolicy(ctx context.Context, site string, p ZonePolicy) (ZonePolicy, error)
	UpdateZonePolicy(ctx context.Context, site string, p ZonePolicy) error
	DeleteZonePolicy(ctx context.Context, site string, id string) error
	ReorderZonePolicies(ctx context.Context, site string, req ZonePolicyReorderRequest) error

	// Traffic Matching Lists — integration v1, zone mode only
	ListTrafficMatchingLists(ctx context.Context, site string) ([]TrafficMatchingList, error)
	CreateTrafficMatchingList(ctx context.Context, site string, list TrafficMatchingList) (TrafficMatchingList, error)
	UpdateTrafficMatchingList(ctx context.Context, site string, list TrafficMatchingList) error
	DeleteTrafficMatchingList(ctx context.Context, site string, id string) error

	// Site and Zone Resolution — integration v1
	GetSiteID(ctx context.Context, siteName string) (string, error)
	GetZoneID(ctx context.Context, site, zoneName string) (string, error)
	DiscoverZones(ctx context.Context, site string) ([]Zone, error)

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
	URL string
}

func (e *ErrNotFound) Error() string {
	if e.URL != "" {
		return "not found: " + e.URL
	}
	return "not found"
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

package storage

import (
	"time"
)

// BanEntry holds metadata about a tracked ban.
type BanEntry struct {
	RecordedAt time.Time
	ExpiresAt  time.Time // zero = never expires
	IPv6       bool
}

// EventEntry records a single ban/unban audit event.
type EventEntry struct {
	Action     string    // "ban" | "unban" | "expire"
	Origin     string    // e.g. "CAPI", "crowdsec", "manual", "expired"
	Scenario   string
	IP         string
	RecordedAt time.Time
}

// GroupRecord is the write-through cache of a UniFi firewall group shard.
type GroupRecord struct {
	UnifiID   string
	Site      string
	Members   []string
	IPv6      bool
	UpdatedAt time.Time
}

// PolicyRecord tracks managed firewall rules and zone policies.
type PolicyRecord struct {
	UnifiID   string
	RuleID    string
	Site      string
	Mode      string // "legacy" or "zone"
	Priority  int
	UpdatedAt time.Time
}

// Store is the persistence interface for the bouncer.
type Store interface {
	// Ban operations
	BanExists(ip string) (bool, error)
	BanRecord(ip string, expiresAt time.Time, ipv6 bool) error
	BanDelete(ip string) error
	BanList() (map[string]BanEntry, error)

	// Janitor helpers
	PruneExpiredBans() (int, error)

	// Group cache
	GetGroup(name string) (*GroupRecord, error)
	SetGroup(name string, rec GroupRecord) error
	DeleteGroup(name string) error
	ListGroups() (map[string]GroupRecord, error)

	// Policy cache
	GetPolicy(name string) (*PolicyRecord, error)
	SetPolicy(name string, rec PolicyRecord) error
	DeletePolicy(name string) error
	ListPolicies() (map[string]PolicyRecord, error)

	// Event history (audit trail)
	RecordEvent(e EventEntry) error
	ListEvents(limit int) ([]EventEntry, error)
	ListEventsForIP(ip string, limit int) ([]EventEntry, error)

	// Utility
	SizeBytes() (int64, error)
	Close() error
}

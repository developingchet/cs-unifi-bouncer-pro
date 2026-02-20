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

	// APIRateGate: rolling-window API budget.
	// Returns allowed=true if within budget; atomically appends timestamp on allowed.
	APIRateGate(endpoint string, window time.Duration, max int) (bool, error)

	// Janitor helpers
	PruneExpiredBans() (int, error)
	PruneExpiredRateEntries(window time.Duration) (int, error)

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

	// Utility
	SizeBytes() (int64, error)
	Close() error
}

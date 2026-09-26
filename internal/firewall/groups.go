package firewall

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/rs/zerolog"
)

// ShardLimit is the maximum number of IPs per Traffic Matching List shard.
// UniFi integration v1 supports up to 10,000 items per TML.
const ShardLimit = 10_000

// TMLPlaceholderV4 and TMLPlaceholderV6 are RFC 5737 / RFC 3849 documentation
// addresses used as placeholder items when creating an empty TML shard.
// The UniFi API rejects empty items arrays on both create and update (HTTP 400).
// These addresses are in reserved documentation ranges and will never match real traffic.
const (
	TMLPlaceholderV4 = "192.0.2.1"   // RFC 5737 TEST-NET-1 (plain IP, not CIDR)
	TMLPlaceholderV6 = "2001:db8::1" // RFC 3849 (plain IP, not CIDR)
)

func addressItemType(value string) string {
	if strings.Contains(value, "/") {
		return "SUBNET"
	}
	return "IP_ADDRESS"
}

// tmlPlaceholderItems returns a slice with the appropriate placeholder IP
// for the given IPv6 flag. This ensures the TML always has at least one item.
func tmlPlaceholderItems(ipv6 bool) []controller.TrafficMatchingListItem {
	val := TMLPlaceholderV4
	if ipv6 {
		val = TMLPlaceholderV6
	}
	return []controller.TrafficMatchingListItem{{Type: "IP_ADDRESS", Value: val}}
}

// ShardState represents the lifecycle state of a shard.
type ShardState uint8

// Shard state constants.
const (
	ShardStatePending  ShardState = iota // allocated in-memory, not yet in UniFi (no IPs assigned)
	ShardStateActive                     // exists in UniFi, has ≥1 real IP
	ShardStateDraining                   // IPs all removed, deletion sequence in progress
)

// Shard represents a single Traffic Matching List shard in zone mode.
// In legacy mode, it represents a firewall group shard.
type Shard struct {
	ID     string     // TML UUID (integration v1) or firewall group ID (legacy), empty if Pending
	Name   string     // "crowdsec-block-v4-0" or similar
	Index  int        // shard number (0, 1, 2, ...)
	Family string     // "v4" or "v6"
	IPs    *IPSet     // in-memory authoritative IP set
	State  ShardState // current lifecycle state
	// activationPending remains set until the group's firewall policies or rules exist.
	activationPending bool

	// onDrainedFired is set to true after onDrained has been called once for
	// this shard. Prevents duplicate policy/rule deletion attempts on retry ticks.
	onDrainedFired bool

	// createFailures counts consecutive failed creates; createRetryAt is the
	// earliest time the next create may be attempted.
	createFailures int
	createRetryAt  time.Time

	// rejected holds members the controller refused for this shard (see
	// putAcceptedMembers). They are left out of every write until released.
	rejected map[string]struct{}
}

// GroupRef keeps a UniFi group ID paired with its actual shard number.
type GroupRef struct {
	Index int
	ID    string
}

var shardNumberPattern = regexp.MustCompile(`[0-9]+`)

// shardIndexForName accepts only names that the configured template renders
// for this site and address family. This also supports index padding and
// templates that contain other numbers (such as a site name).
func (sm *ShardManager) shardIndexForName(name string) (int, bool) {
	for _, number := range shardNumberPattern.FindAllString(name, -1) {
		idx, err := strconv.Atoi(number)
		if err != nil {
			continue
		}
		rendered, err := sm.namer.GroupName(NameData{Family: Family(sm.ipv6), Index: idx, Site: sm.site})
		if err == nil && rendered == name {
			return idx, true
		}
	}
	return 0, false
}

// orphanedGroup represents a placeholder-only UniFi group found during EnsureShards
// that should be deleted (policies/rules first, then the group itself).
type orphanedGroup struct {
	UnifiID string // group ID in UniFi
	Name    string // group name (for logging)
}

// ShardFamily tracks shard state and unique IP ownership for one IP family.
type ShardFamily struct {
	Shards []*Shard
	// ipOwner maps each banned IP to the shard index that owns it.
	// Guarded by ShardManager.mu.
	ipOwner map[string]int
}

// ShardManager manages a set of firewall group shards for one address family on one site.
// In zone mode, shards are Traffic Matching Lists; in legacy mode, they are firewall groups.
type ShardManager struct {
	mu         sync.RWMutex
	site       string
	ipv6       bool
	family     string
	shardLimit int
	namer      *Namer
	ctrl       controller.Controller
	store      storage.Store
	log        zerolog.Logger
	flushDelay time.Duration
	flushSem   chan struct{} // shared semaphore; nil = unlimited
	dryRun     bool
	mode       string // "legacy" or "zone" (used for log messaging only)

	// fam holds the shard state for this manager's address family
	// ("v4" for ipv6=false, "v6" for ipv6=true). Guarded by mu.
	fam *ShardFamily

	// onActivated is called when a Pending shard becomes Active (transitions to UniFi after first flush).
	// Called with (ctx, shardIdx, groupID).
	onActivated func(ctx context.Context, shardIdx int, groupID string) error

	// onRateLimit is called when a shard sync returns ErrRateLimit.
	// The manager uses this to back off future flushes.
	onRateLimit func(retryAfter time.Duration)

	// onSyncError is called when a shard PUT fails (non-rate-limit errors).
	// The manager uses this to trip the circuit breaker.
	onSyncError func()

	// onSyncSuccess is called after a successful shard PUT.
	// The manager uses this to reset the circuit breaker.
	onSyncSuccess func()

	// onDrained is called when a Draining shard is about to have its UniFi object
	// deleted. The callback should delete the shard's policies/rules first so UniFi
	// does not reject the group deletion due to remaining references.
	// Called with (ctx, shardIdx, groupID).
	onDrained func(ctx context.Context, shardIdx int, groupID string) error

	// mergeThreshold is the IP count at or below which a shard is eligible for
	// consolidation into a larger shard. 0 = auto (shardLimit/2). -1 = disabled.
	mergeThreshold int

	// orphanedGroups is populated by EnsureShards with placeholder-only groups found in UniFi.
	// These groups should be deleted (policies/rules first, then the group).
	// Guarded by mu.
	orphanedGroups []orphanedGroup
}

// NewShardManager creates a ShardManager. Call EnsureShards to initialize from the API.
func NewShardManager(site string, ipv6 bool, capacity int, namer *Namer,
	ctrl controller.Controller, store storage.Store, log zerolog.Logger,
	flushDelay time.Duration, flushSem chan struct{}, dryRun bool, mode string) *ShardManager {
	if mode == "" {
		mode = "legacy"
	}

	family := Family(ipv6)
	limit := capacity
	if limit <= 0 {
		limit = ShardLimit
	}

	return &ShardManager{
		site:       site,
		ipv6:       ipv6,
		family:     family,
		shardLimit: limit,
		namer:      namer,
		ctrl:       ctrl,
		store:      store,
		log:        log,
		flushDelay: flushDelay,
		flushSem:   flushSem,
		dryRun:     dryRun,
		mode:       mode,
		fam: &ShardFamily{
			Shards:  []*Shard{},
			ipOwner: make(map[string]int),
		},
	}
}

// SetActivationCallback sets the function to be called when a shard transitions from Pending to Active.
// Called during syncShard() with (ctx, shardIdx, groupID).
func (sm *ShardManager) SetActivationCallback(fn func(ctx context.Context, shardIdx int, groupID string) error) {
	sm.onActivated = fn
}

// SetRateLimitCallback sets the function to be called when a shard sync returns ErrRateLimit.
func (sm *ShardManager) SetRateLimitCallback(fn func(retryAfter time.Duration)) {
	sm.onRateLimit = fn
}

// SetSyncCallbacks sets callbacks for shard sync success and non-rate-limit errors.
// Used by the manager to drive the circuit breaker.
func (sm *ShardManager) SetSyncCallbacks(onSuccess func(), onError func()) {
	sm.onSyncSuccess = onSuccess
	sm.onSyncError = onError
}

// SetDrainCallback sets the function called when a Draining shard is about to have
// its UniFi object deleted. The callback must remove the shard's policies/rules first.
func (sm *ShardManager) SetDrainCallback(fn func(ctx context.Context, shardIdx int, groupID string) error) {
	sm.onDrained = fn
}

// SetMergeThreshold configures the IP count at or below which a shard is eligible
// for consolidation. 0 = auto (shardLimit/2). -1 = disable rebalancing.
func (sm *ShardManager) SetMergeThreshold(n int) {
	sm.mergeThreshold = n
}

// TakeOrphanedGroups returns and clears the list of placeholder-only groups found during EnsureShards.
// These are groups that exist in UniFi but contain only placeholder IPs and should be deleted.
func (sm *ShardManager) TakeOrphanedGroups() []orphanedGroup {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	result := sm.orphanedGroups
	sm.orphanedGroups = nil
	return result
}

func (sm *ShardManager) shardObjectKind() string {
	if sm.mode == "zone" {
		return "traffic matching list"
	}
	return "firewall group"
}

func (sm *ShardManager) findShardByIndexLocked(family *ShardFamily, shardIdx int) *Shard {
	for _, shard := range family.Shards {
		if shard.Index == shardIdx {
			return shard
		}
	}
	return nil
}

// AddIP adds ip to the appropriate shard of this manager's address family.
// If ip is already tracked in any shard, it is a no-op (deduplication).
// If all shards are full or draining, a new Pending shard is allocated
// in-memory and the IP is placed into it immediately. The shard will be
// created in UniFi on the next flush.
//
// The lock is held for the entire operation. allocShard is pure in-memory
// (template rendering + struct creation, no I/O) so there is no reason to
// drop the lock between the capacity check and the append, which previously
// created a TOCTOU race: concurrent goroutines could all compute the same
// nextIndex, one would win the re-lock and create the shard, and the rest
// would find that shard already full and return an error.
func (sm *ShardManager) AddIP(_ context.Context, ip string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.addIPLocked(ip)
	return nil
}

// addIPLocked places ip and returns the index of the shard that holds it and
// whether that shard was allocated by this call. Callers hold sm.mu.
func (sm *ShardManager) addIPLocked(ip string) (owner int, allocated bool) {
	family := sm.fam

	if idx, owned := family.ipOwner[ip]; owned {
		return idx, false
	}

	for _, shard := range family.Shards {
		if shard.State == ShardStateDraining {
			continue // draining shards cannot accept new IPs
		}
		if shard.IPs.Capacity(sm.shardLimit) > 0 {
			shard.IPs.Add(ip)
			family.ipOwner[ip] = shard.Index
			sm.updateMetricsLocked()
			return shard.Index, false
		}
	}

	// All existing shards are full or draining — allocate a new Pending shard.
	nextIndex := 0
	for _, existing := range family.Shards {
		if existing.Index >= nextIndex {
			nextIndex = existing.Index + 1
		}
	}
	shard := sm.allocShard(nextIndex)
	family.Shards = append(family.Shards, shard)
	shard.IPs.Add(ip)
	family.ipOwner[ip] = shard.Index
	sm.updateMetricsLocked()
	return shard.Index, true
}

// RemoveIP removes ip from whichever shard owns it. No-op if not tracked.
func (sm *ShardManager) RemoveIP(ip string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	family := sm.fam
	shardIdx, owned := family.ipOwner[ip]
	if !owned {
		return
	}

	if shard := sm.findShardByIndexLocked(family, shardIdx); shard != nil {
		shard.IPs.Remove(ip)
	}
	delete(family.ipOwner, ip)
	sm.updateMetricsLocked()
}

// Add adds an IP to the manager family and returns shard details for callers
// that need to provision rule/policy infrastructure when a new shard appears.
// newShardIdx is the index of a shard this call allocated, or -1. It is
// decided under the lock, so concurrent adds never both report one shard.
func (sm *ShardManager) Add(_ context.Context, ip string) (shardName string, newShardIdx int, err error) {
	sm.mu.Lock()
	ownerIdx, allocated := sm.addIPLocked(ip)
	sm.mu.Unlock()

	name, err := sm.namer.GroupName(NameData{Family: Family(sm.ipv6), Index: ownerIdx, Site: sm.site})
	if err != nil {
		return "", -1, err
	}
	newShardIdx = -1
	if allocated {
		newShardIdx = ownerIdx
	}
	return name, newShardIdx, nil
}

// Remove removes an IP from whichever shard contains it.
func (sm *ShardManager) Remove(ctx context.Context, ip string) (string, error) {
	sm.mu.RLock()
	family := sm.fam
	shardIdx, owned := family.ipOwner[ip]
	sm.mu.RUnlock()
	if !owned {
		return "", nil
	}

	sm.RemoveIP(ip)

	name, err := sm.namer.GroupName(NameData{Family: Family(sm.ipv6), Index: shardIdx, Site: sm.site})
	if err != nil {
		return "", err
	}
	return name, nil
}

// Contains returns true if any shard contains the given IP.
func (sm *ShardManager) Contains(ip string) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	family := sm.fam
	_, ok := family.ipOwner[ip]
	return ok
}

// AllMembers returns all IPs across all shards.
func (sm *ShardManager) AllMembers() []string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	family := sm.fam
	var all []string
	for _, s := range family.Shards {
		all = append(all, s.IPs.Members()...)
	}
	return all
}

// GroupRefs returns Active group IDs paired with their actual shard indices.
// Pending and Draining shards must not receive new policies.
func (sm *ShardManager) GroupRefs() []GroupRef {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	family := sm.fam
	refs := make([]GroupRef, 0, len(family.Shards))
	for _, s := range family.Shards {
		if s.State == ShardStateActive && s.ID != "" {
			refs = append(refs, GroupRef{Index: s.Index, ID: s.ID})
		}
	}
	return refs
}

// OwnedRefs returns Active and Draining shards that exist on the controller.
// Their policies and rules must survive an orphan sweep: a Draining shard's
// are removed only by its drain callback, once its IPs have moved.
func (sm *ShardManager) OwnedRefs() []GroupRef {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	family := sm.fam
	refs := make([]GroupRef, 0, len(family.Shards))
	for _, s := range family.Shards {
		if s.State != ShardStatePending && s.ID != "" {
			refs = append(refs, GroupRef{Index: s.Index, ID: s.ID})
		}
	}
	return refs
}

func (sm *ShardManager) GroupIDAt(shardIdx int) string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	for _, shard := range sm.fam.Shards {
		if shard.Index == shardIdx && shard.State == ShardStateActive {
			return shard.ID
		}
	}
	return ""
}

// GroupIDs returns UniFi IDs of Active and Draining shards for deletion paths.
func (sm *ShardManager) GroupIDs() []string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	family := sm.fam
	ids := make([]string, 0, len(family.Shards))
	for _, shard := range family.Shards {
		if shard.State != ShardStatePending && shard.ID != "" {
			ids = append(ids, shard.ID)
		}
	}
	return ids
}

func (sm *ShardManager) updateMetricsLocked() {
	family := sm.fam
	familyName := Family(sm.ipv6)
	unsynced := 0
	for _, s := range family.Shards {
		// A shard enforces nothing until it exists and has its block policy or rule.
		if s.ID == "" || s.activationPending {
			unsynced += s.IPs.Len()
		} else {
			unsynced += len(s.rejected)
		}
		name := s.Name // rendered once at allocation; this runs on every add
		count := float64(s.IPs.Len())
		metrics.FirewallGroupSize.WithLabelValues(familyName, name, sm.site).Set(count)
		if sm.shardLimit > 0 {
			metrics.ShardOccupancy.WithLabelValues(familyName, name, sm.site).Set(count / float64(sm.shardLimit))
		}
	}
	metrics.UnsyncedIPs.WithLabelValues(familyName, sm.site).Set(float64(unsynced))
}

func tmlTypeForFamily(family string) string {
	if family == "v6" {
		return "IPV6_ADDRESSES"
	}
	return "IPV4_ADDRESSES"
}

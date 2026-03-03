package firewall

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/rs/zerolog"
)

// ZoneConfig holds configuration for zone-based firewall mode.
type ZoneConfig struct {
	ZonePairs   []config.ZonePair
	Description string
	LogDrops    bool
	APIWriteDelay time.Duration
}

// ZoneManager manages zone-based firewall policies.
type ZoneManager struct {
	cfg   ZoneConfig
	namer *Namer
	ctrl  controller.Controller
	store storage.Store
	log   zerolog.Logger

	mu        sync.RWMutex
	zoneCache map[string]map[string]string // site -> zone name -> zone ID
}

// NewZoneManager constructs a ZoneManager.
func NewZoneManager(cfg ZoneConfig, namer *Namer, ctrl controller.Controller, store storage.Store, log zerolog.Logger) *ZoneManager {
	return &ZoneManager{cfg: cfg, namer: namer, ctrl: ctrl, store: store, log: log}
}

// Bootstrap performs fail-fast startup discovery for all configured sites:
//  1. Resolves each site name to its integration v1 UUID (fails if missing).
//  2. Fetches all firewall zones for each site (fails if unavailable).
//  3. At DEBUG log level, emits a structured log for each discovered zone.
func (zm *ZoneManager) Bootstrap(ctx context.Context, sites []string) error {
	for _, site := range sites {
		siteID, err := zm.ctrl.GetSiteID(ctx, site)
		if err != nil {
			return fmt.Errorf("resolve site UUID for %q: %w", site, err)
		}
		zm.log.Info().Str("site", site).Str("site_id", siteID).Msg("site UUID resolved")

		zones, err := zm.ctrl.DiscoverZones(ctx, site)
		if err != nil {
			return fmt.Errorf("discover firewall zones for site %q: %w", site, err)
		}
		zm.log.Info().Str("site", site).Int("zone_count", len(zones)).Msg("zone discovery complete")

		// Emit per-zone debug log when log level is DEBUG.
		if zm.log.GetLevel() <= zerolog.DebugLevel {
			for _, z := range zones {
				zm.log.Debug().
					Str("site", site).
					Str("zone_name", z.Name).
					Str("zone_id", z.ID).
					Str("origin", z.Origin).
					Msg("discovered zone")
			}
		}

		// Populate zone cache for this site.
		siteZones := make(map[string]string)
		for _, pair := range zm.cfg.ZonePairs {
			for _, name := range []string{pair.Src, pair.Dst} {
				if _, ok := siteZones[name]; ok {
					continue
				}
				id, err := zm.ctrl.GetZoneID(ctx, site, name)
				if err != nil {
					return fmt.Errorf("cache zone %q for site %q: %w", name, site, err)
				}
				siteZones[name] = id
			}
		}
		zm.mu.Lock()
		if zm.zoneCache == nil {
			zm.zoneCache = make(map[string]map[string]string)
		}
		zm.zoneCache[site] = siteZones
		zm.mu.Unlock()
	}
	return nil
}

// Reload updates the zone pair configuration and repopulates the zone ID cache
// for all given sites. All zone IDs are resolved into a staging map first; the
// live cache is updated only if every zone resolves successfully (validate-then-commit).
// Safe to call concurrently with read operations.
func (zm *ZoneManager) Reload(ctx context.Context, sites []string, pairs []config.ZonePair) error {
	// Stage all resolutions before acquiring the write lock.
	staged := make(map[string]map[string]string, len(sites))
	var firstErr error

	for _, site := range sites {
		// 1A: Evict stale cache entries so GetZoneID hits the API.
		zm.ctrl.InvalidateZoneCache(site)

		siteZones := make(map[string]string)
		allOK := true
		for _, pair := range pairs {
			for _, name := range []string{pair.Src, pair.Dst} {
				if _, ok := siteZones[name]; ok {
					continue
				}
				id, err := zm.ctrl.GetZoneID(ctx, site, name)
				if err != nil {
					zm.log.Warn().Err(err).Str("site", site).Str("zone", name).
						Msg("reload: failed to resolve zone ID; aborting update for this site")
					if firstErr == nil {
						firstErr = fmt.Errorf("reload zone %q for site %q: %w", name, site, err)
					}
					allOK = false
					break
				}
				siteZones[name] = id
			}
			if !allOK {
				break
			}
		}

		// 1B: Only commit if all zones resolved successfully.
		if allOK {
			staged[site] = siteZones
		}
	}

	// Commit validated sites atomically.
	if len(staged) > 0 {
		zm.mu.Lock()
		if zm.zoneCache == nil {
			zm.zoneCache = make(map[string]map[string]string)
		}
		for site, siteZones := range staged {
			zm.zoneCache[site] = siteZones
		}
		zm.cfg.ZonePairs = pairs
		zm.mu.Unlock()
	}

	return firstErr
}

// EnsurePolicies idempotently creates zone policies for each shard and zone pair.
func (zm *ZoneManager) EnsurePolicies(ctx context.Context, site string, v4Shards, v6Shards *ShardManager) error {
	zm.mu.RLock()
	zoneMap, ok := zm.zoneCache[site]
	zm.mu.RUnlock()
	if !ok {
		return fmt.Errorf("zone cache not populated for site %q — was Bootstrap called?", site)
	}
	for _, pair := range zm.cfg.ZonePairs {
		if _, ok := zoneMap[pair.Src]; !ok {
			return fmt.Errorf("zone %q not in cache for site %q", pair.Src, site)
		}
		if _, ok := zoneMap[pair.Dst]; !ok {
			return fmt.Errorf("zone %q not in cache for site %q", pair.Dst, site)
		}
	}

	// Fetch ALL existing policies once for all zone pairs (avoids one GET per pair).
	existingPolicies, err := zm.ctrl.ListZonePolicies(ctx, site)
	if err != nil {
		return err
	}
	existingByID := make(map[string]controller.ZonePolicy, len(existingPolicies))
	for _, p := range existingPolicies {
		existingByID[p.ID] = p
	}

	for _, pair := range zm.cfg.ZonePairs {
		// ConnectionStateFilter = nil means "All" states in UniFi API.
		if err := zm.ensurePoliciesForPair(ctx, site, pair, zoneMap, existingByID, false, v4Shards); err != nil {
			return err
		}
		if v6Shards != nil {
			if err := zm.ensurePoliciesForPair(ctx, site, pair, zoneMap, existingByID, true, v6Shards); err != nil {
				return err
			}
		}
	}

	return nil
}

func (zm *ZoneManager) ensurePoliciesForPair(ctx context.Context, site string, pair config.ZonePair, zoneMap map[string]string, existingByID map[string]controller.ZonePolicy, ipv6 bool, sm *ShardManager) error {
	family := Family(ipv6)
	ipVersion := "IPV4"
	if ipv6 {
		ipVersion = "IPV6"
	}

	groupIDs := sm.GroupIDs()
	srcZoneID := zoneMap[pair.Src]
	dstZoneID := zoneMap[pair.Dst]

	firstCreate := true
	for i, groupID := range groupIDs {
		policyName, err := zm.namer.PolicyName(NameData{
			Family:  family,
			Index:   i,
			Site:    site,
			SrcZone: pair.Src,
			DstZone: pair.Dst,
		})
		if err != nil {
			return err
		}

		existing, lookupErr := zm.store.GetPolicy(policyName)
		if lookupErr != nil {
			return fmt.Errorf("lookup policy %s: %w", policyName, lookupErr)
		}

		// Check if policy exists in API and needs update (reconcile mode)
		if existing != nil && existing.UnifiID != "" {
			if apiPolicy, found := existingByID[existing.UnifiID]; found {
				if needsUpdateZonePolicy(&apiPolicy, groupID) {
					zm.log.Info().Str("policy", policyName).Msg("zone policy needs update, applying reconcile")
					updateErr := zm.updateZonePolicy(ctx, site, apiPolicy, groupID)
					if updateErr != nil {
						var nf *controller.ErrNotFound
						if !errors.As(updateErr, &nf) {
							return fmt.Errorf("update zone policy %s: %w", policyName, updateErr)
						}
						// 404 on PUT: policy was externally deleted; clear bbolt and fall through to create.
						zm.log.Warn().Str("policy", policyName).Str("id", existing.UnifiID).
							Msg("zone policy not found on update (externally deleted?); clearing record for re-creation")
						_ = zm.store.DeletePolicy(policyName)
					} else {
						continue
					}
				} else {
					zm.log.Debug().Str("policy", policyName).Msg("zone policy already exists")
					continue
				}
			}
			// Not found in API — fall through to create
		}

		// Apply delay between consecutive creates (not before the first one)
		if !firstCreate && zm.cfg.APIWriteDelay > 0 {
			select {
			case <-time.After(zm.cfg.APIWriteDelay):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		firstCreate = false

		// groupID is the TML UUID in zone mode (integration v1).
		// ConnectionStateFilter = nil means "All" states in UniFi API.
		if groupID == "" {
			return fmt.Errorf("shard %d for %s->%s has empty TML ID — cannot create block policy without source filter", i, pair.Src, pair.Dst)
		}
		policy := controller.ZonePolicy{
			Name:                   policyName,
			Enabled:                true,
			Action:                 "BLOCK",
			Description:            zm.cfg.Description,
			SrcZone:                srcZoneID,
			DstZone:                dstZoneID,
			IPVersion:              ipVersion,
			TrafficMatchingListIDs: []string{groupID},
			ConnectionStateFilter:  nil, // nil = All connection states
			LoggingEnabled:         zm.cfg.LogDrops,
		}

		created, err := zm.ctrl.CreateZonePolicy(ctx, site, policy)
		if err != nil {
			var conflict *controller.ErrConflict
			if errors.As(err, &conflict) {
				if id := zm.findExistingPolicyByName(ctx, site, policyName); id != "" {
					zm.log.Warn().Str("policy", policyName).Str("id", id).
						Msg("zone policy already exists (409 conflict); recovering existing ID")
					if storeErr := zm.store.SetPolicy(policyName, storage.PolicyRecord{UnifiID: id, Site: site, Mode: "zone"}); storeErr != nil {
						zm.log.Warn().Err(storeErr).Str("policy", policyName).Msg("failed to cache recovered policy in bbolt")
					}
					existingByID[id] = controller.ZonePolicy{ID: id}
					continue
				}
			}
			return fmt.Errorf("create zone policy %s: %w", policyName, err)
		}
		existingByID[created.ID] = created

		if err := zm.store.SetPolicy(policyName, storage.PolicyRecord{
			UnifiID: created.ID,
			Site:    site,
			Mode:    "zone",
		}); err != nil {
			zm.log.Warn().Err(err).Str("policy", policyName).Msg("failed to cache policy in bbolt")
		}

		zm.log.Info().Str("name", policyName).Str("id", created.ID).
			Str("src", pair.Src).Str("dst", pair.Dst).Msg("created zone policy")
	}

	return nil
}

// EnsurePoliciesForShard creates zone policies for a single new shard across all configured zone pairs.
// Called when a new shard overflows mid-operation.
func (zm *ZoneManager) EnsurePoliciesForShard(ctx context.Context, site, groupID string, ipv6 bool, shardIdx int) error {
	family := Family(ipv6)
	ipVersion := "IPV4"
	if ipv6 {
		ipVersion = "IPV6"
	}

	zm.mu.RLock()
	zoneMap, ok := zm.zoneCache[site]
	zm.mu.RUnlock()
	if !ok {
		return fmt.Errorf("zone cache not populated for site %q — was Bootstrap called?", site)
	}
	for _, pair := range zm.cfg.ZonePairs {
		if _, ok := zoneMap[pair.Src]; !ok {
			return fmt.Errorf("zone %q not in cache for site %q", pair.Src, site)
		}
		if _, ok := zoneMap[pair.Dst]; !ok {
			return fmt.Errorf("zone %q not in cache for site %q", pair.Dst, site)
		}
	}

	existingPolicies, err := zm.ctrl.ListZonePolicies(ctx, site)
	if err != nil {
		return fmt.Errorf("list policies for shard %d: %w", shardIdx, err)
	}
	existingByUnifiID := make(map[string]bool, len(existingPolicies))
	for _, p := range existingPolicies {
		existingByUnifiID[p.ID] = true
	}

	for _, pair := range zm.cfg.ZonePairs {
		policyName, err := zm.namer.PolicyName(NameData{
			Family:  family,
			Index:   shardIdx,
			Site:    site,
			SrcZone: pair.Src,
			DstZone: pair.Dst,
		})
		if err != nil {
			return err
		}

		existing, lookupErr := zm.store.GetPolicy(policyName)
		if lookupErr != nil {
			return fmt.Errorf("lookup policy %s: %w", policyName, lookupErr)
		}

		if existing != nil && existing.UnifiID != "" && existingByUnifiID[existing.UnifiID] {
			zm.log.Debug().Str("policy", policyName).Msg("zone policy already exists for new shard")
			continue
		}

		srcZoneID := zoneMap[pair.Src]
		dstZoneID := zoneMap[pair.Dst]

		if groupID == "" {
			return fmt.Errorf("new shard %d for %s->%s has empty TML ID — cannot create block policy without source filter", shardIdx, pair.Src, pair.Dst)
		}
		policy := controller.ZonePolicy{
			Name:                   policyName,
			Enabled:                true,
			Action:                 "BLOCK",
			Description:            zm.cfg.Description,
			SrcZone:                srcZoneID,
			DstZone:                dstZoneID,
			IPVersion:              ipVersion,
			TrafficMatchingListIDs: []string{groupID},
			ConnectionStateFilter:  nil, // nil = All connection states
			LoggingEnabled:         zm.cfg.LogDrops,
		}

		created, err := zm.ctrl.CreateZonePolicy(ctx, site, policy)
		if err != nil {
			var conflict *controller.ErrConflict
			if errors.As(err, &conflict) {
				if id := zm.findExistingPolicyByName(ctx, site, policyName); id != "" {
					zm.log.Warn().Str("policy", policyName).Str("id", id).
						Msg("zone policy already exists (409 conflict); recovering existing ID")
					if storeErr := zm.store.SetPolicy(policyName, storage.PolicyRecord{UnifiID: id, Site: site, Mode: "zone"}); storeErr != nil {
						zm.log.Warn().Err(storeErr).Str("policy", policyName).Msg("failed to cache recovered policy in bbolt")
					}
					continue
				}
			}
			return fmt.Errorf("create zone policy %s: %w", policyName, err)
		}

		if err := zm.store.SetPolicy(policyName, storage.PolicyRecord{
			UnifiID: created.ID,
			Site:    site,
			Mode:    "zone",
		}); err != nil {
			zm.log.Warn().Err(err).Str("policy", policyName).Msg("failed to cache policy in bbolt")
		}

		zm.log.Info().Str("name", policyName).Str("id", created.ID).
			Msg("created zone policy for new shard")
	}
	return nil
}

// DeletePoliciesForShard deletes all zone policies for the given shard across all zone pairs.
// Called during shard pruning.
func (zm *ZoneManager) DeletePoliciesForShard(ctx context.Context, site string, ipv6 bool, shardIdx int) error {
	family := Family(ipv6)

	for _, pair := range zm.cfg.ZonePairs {
		policyName, err := zm.namer.PolicyName(NameData{
			Family:  family,
			Index:   shardIdx,
			Site:    site,
			SrcZone: pair.Src,
			DstZone: pair.Dst,
		})
		if err != nil {
			return err
		}

		existing, lookupErr := zm.store.GetPolicy(policyName)
		if lookupErr != nil {
			return fmt.Errorf("lookup policy %s: %w", policyName, lookupErr)
		}

		if existing == nil || existing.UnifiID == "" {
			continue // Already gone
		}

		if err := zm.ctrl.DeleteZonePolicy(ctx, site, existing.UnifiID); err != nil {
			return fmt.Errorf("delete zone policy %s: %w", policyName, err)
		}

		if err := zm.store.DeletePolicy(policyName); err != nil {
			zm.log.Warn().Err(err).Str("policy", policyName).Msg("failed to delete policy from bbolt")
		}

		zm.log.Info().Str("name", policyName).Msg("deleted zone policy for pruned shard")
	}
	return nil
}

// DeletePolicies removes all managed zone policies for a site.
func (zm *ZoneManager) DeletePolicies(ctx context.Context, site string) error {
	policies, err := zm.store.ListPolicies()
	if err != nil {
		return err
	}
	for name, rec := range policies {
		if rec.Site != site || rec.Mode != "zone" {
			continue
		}
		if err := zm.ctrl.DeleteZonePolicy(ctx, site, rec.UnifiID); err != nil {
			zm.log.Warn().Err(err).Str("policy", name).Msg("failed to delete zone policy")
			continue
		}
		if err := zm.store.DeletePolicy(name); err != nil {
			zm.log.Warn().Err(err).Str("policy", name).Msg("failed to delete policy from bbolt")
		}
	}
	return nil
}

// UpdateGroupReference updates zone policies that reference an old TML/group ID with a new one.
func (zm *ZoneManager) UpdateGroupReference(ctx context.Context, site, oldGroupID, newGroupID string) error {
	policies, err := zm.ctrl.ListZonePolicies(ctx, site)
	if err != nil {
		return err
	}
	for _, p := range policies {
		needsUpdate := false
		for i, id := range p.TrafficMatchingListIDs {
			if id == oldGroupID {
				p.TrafficMatchingListIDs[i] = newGroupID
				needsUpdate = true
			}
		}
		if needsUpdate {
			if err := zm.ctrl.UpdateZonePolicy(ctx, site, p); err != nil {
				return fmt.Errorf("update zone policy %s: %w", p.ID, err)
			}
		}
	}
	return nil
}

// needsUpdateZonePolicy returns true if the policy needs to be updated to match the desired state.
// It checks for two conditions:
// 1. ConnectionStateFilter is not nil ( UniFi API will show "Custom" instead of "All")
// 2. TrafficMatchingListIDs is empty or has the wrong TML ID
func needsUpdateZonePolicy(policy *controller.ZonePolicy, desiredTMLID string) bool {
	// ConnectionStateFilter should be nil for "All" states
	if policy.ConnectionStateFilter != nil {
		return true
	}
	// TrafficMatchingListIDs should have exactly one entry with the desired TML ID
	if len(policy.TrafficMatchingListIDs) != 1 || policy.TrafficMatchingListIDs[0] != desiredTMLID {
		return true
	}
	return false
}

// updateZonePolicy updates an existing zone policy with the correct settings.
func (zm *ZoneManager) updateZonePolicy(ctx context.Context, site string, policy controller.ZonePolicy, newGroupID string) error {
	policy.TrafficMatchingListIDs = []string{newGroupID}
	policy.ConnectionStateFilter = nil
	policy.LoggingEnabled = zm.cfg.LogDrops
	return zm.ctrl.UpdateZonePolicy(ctx, site, policy)
}

// findExistingPolicyByName queries the UniFi API for a zone policy with the given name.
// Used for 409 conflict recovery: if CreateZonePolicy returns ErrConflict, the policy
// already exists and we can recover its ID to continue without re-creating.
func (zm *ZoneManager) findExistingPolicyByName(ctx context.Context, site, name string) string {
	policies, err := zm.ctrl.ListZonePolicies(ctx, site)
	if err != nil {
		return ""
	}
	for _, p := range policies {
		if p.Name == name {
			return p.ID
		}
	}
	return ""
}

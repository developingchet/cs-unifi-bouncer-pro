package firewall

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/rs/zerolog"
)

// ZoneConfig holds configuration for zone-based firewall mode.
type ZoneConfig struct {
	ZonePairs            []config.ZonePair
	ZoneConnectionStates []string
	PolicyReorder        bool
	Description          string
	LogDrops             bool
	APIWriteDelay        time.Duration
}

// ZoneManager manages zone-based firewall policies.
type ZoneManager struct {
	cfg   ZoneConfig
	namer *Namer
	ctrl  controller.Controller
	store storage.Store
	log   zerolog.Logger
}

// NewZoneManager constructs a ZoneManager.
func NewZoneManager(cfg ZoneConfig, namer *Namer, ctrl controller.Controller, store storage.Store, log zerolog.Logger) *ZoneManager {
	return &ZoneManager{cfg: cfg, namer: namer, ctrl: ctrl, store: store, log: log}
}

func normalizeConnectionStates(states []string) []string {
	out := make([]string, 0, len(states))
	for _, state := range states {
		upper := strings.ToUpper(strings.TrimSpace(state))
		if upper == "" {
			continue
		}
		out = append(out, upper)
	}
	return out
}

// EnsurePolicies idempotently creates zone policies for each shard and zone pair.
func (zm *ZoneManager) EnsurePolicies(ctx context.Context, site string, v4Shards, v6Shards *ShardManager) error {
	zoneMap := make(map[string]string)
	for _, pair := range zm.cfg.ZonePairs {
		// For UDM Pro Max 10.x, zone names cannot be auto-resolved.
		// Zone IDs must be 24-char hex ObjectIDs passed directly via ZONE_PAIRS.
		// GetZoneID will return the value directly if it's a valid ObjectID.
		srcZoneID, err := zm.ctrl.GetZoneID(ctx, site, pair.Src)
		if err != nil {
			return fmt.Errorf("resolve source zone %q: %w", pair.Src, err)
		}
		dstZoneID, err := zm.ctrl.GetZoneID(ctx, site, pair.Dst)
		if err != nil {
			return fmt.Errorf("resolve destination zone %q: %w", pair.Dst, err)
		}
		zoneMap[pair.Src] = srcZoneID
		zoneMap[pair.Dst] = dstZoneID
	}

	connectionStates := normalizeConnectionStates(zm.cfg.ZoneConnectionStates)

	for _, pair := range zm.cfg.ZonePairs {
		if err := zm.ensurePoliciesForPair(ctx, site, pair, zoneMap, connectionStates, false, v4Shards); err != nil {
			return err
		}
		if v6Shards != nil {
			if err := zm.ensurePoliciesForPair(ctx, site, pair, zoneMap, connectionStates, true, v6Shards); err != nil {
				return err
			}
		}
	}

	// Reorder once after all families and zone-pairs are ensured.
	if zm.cfg.PolicyReorder {
		if err := zm.reorderPolicies(ctx, site); err != nil {
			zm.log.Warn().Err(err).Str("site", site).Msg("policy reorder failed")
		}
	}

	return nil
}

func (zm *ZoneManager) ensurePoliciesForPair(ctx context.Context, site string, pair config.ZonePair, zoneMap map[string]string, connectionStates []string, ipv6 bool, sm *ShardManager) error {
	family := Family(ipv6)
	ipVersion := "IPV4"
	if ipv6 {
		ipVersion = "IPV6"
	}

	groupIDs := sm.GroupIDs()

	// Fetch ALL existing policies once before the loop (avoids N redundant GETs).
	existingPolicies, err := zm.ctrl.ListZonePolicies(ctx, site)
	if err != nil {
		return err
	}
	existingByID := make(map[string]bool, len(existingPolicies))
	for _, p := range existingPolicies {
		existingByID[p.ID] = true
	}

	// Resolve zone names to UUIDs
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

		if existing != nil && existing.UnifiID != "" && existingByID[existing.UnifiID] {
			zm.log.Debug().Str("policy", policyName).Msg("zone policy already exists")
			continue
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

		// groupID is a firewall group ID in zone mode
		policy := controller.ZonePolicy{
			Name:                   policyName,
			Enabled:                true,
			Action:                 "BLOCK",
			Description:            zm.cfg.Description,
			SrcZone:                srcZoneID,
			DstZone:                dstZoneID,
			IPVersion:              ipVersion,
			TrafficMatchingListIDs: []string{groupID},
			ConnectionStateFilter:  connectionStates,
			LoggingEnabled:         zm.cfg.LogDrops,
		}

		created, err := zm.ctrl.CreateZonePolicy(ctx, site, policy)
		if err != nil {
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

	zoneMap := make(map[string]string)
	for _, pair := range zm.cfg.ZonePairs {
		// For UDM Pro Max 10.x, zone names cannot be auto-resolved.
		// Zone IDs must be 24-char hex ObjectIDs passed directly via ZONE_PAIRS.
		srcZoneID, err := zm.ctrl.GetZoneID(ctx, site, pair.Src)
		if err != nil {
			return fmt.Errorf("resolve source zone %q: %w", pair.Src, err)
		}
		dstZoneID, err := zm.ctrl.GetZoneID(ctx, site, pair.Dst)
		if err != nil {
			return fmt.Errorf("resolve destination zone %q: %w", pair.Dst, err)
		}
		zoneMap[pair.Src] = srcZoneID
		zoneMap[pair.Dst] = dstZoneID
	}
	connectionStates := normalizeConnectionStates(zm.cfg.ZoneConnectionStates)

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

		if existing != nil && existing.UnifiID != "" {
			// Verify it still exists in the API
			policies, apiErr := zm.ctrl.ListZonePolicies(ctx, site)
			if apiErr != nil {
				return apiErr
			}
			found := false
			for _, p := range policies {
				if p.ID == existing.UnifiID {
					found = true
					break
				}
			}
			if found {
				zm.log.Debug().Str("policy", policyName).Msg("zone policy already exists for new shard")
				continue
			}
		}

		// Resolve zone names to UUIDs for this pair
		srcZoneID := zoneMap[pair.Src]
		dstZoneID := zoneMap[pair.Dst]

		policy := controller.ZonePolicy{
			Name:                   policyName,
			Enabled:                true,
			Action:                 "BLOCK",
			Description:            zm.cfg.Description,
			SrcZone:                srcZoneID,
			DstZone:                dstZoneID,
			IPVersion:              ipVersion,
			TrafficMatchingListIDs: []string{groupID},
			ConnectionStateFilter:  connectionStates,
			LoggingEnabled:         zm.cfg.LogDrops,
		}

		created, err := zm.ctrl.CreateZonePolicy(ctx, site, policy)
		if err != nil {
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

// reorderPolicies moves all bouncer-managed policies to the top, per zone-pair.
func (zm *ZoneManager) reorderPolicies(ctx context.Context, site string) error {
	allPolicies, err := zm.ctrl.ListZonePolicies(ctx, site)
	if err != nil {
		return err
	}

	stored, err := zm.store.ListPolicies()
	if err != nil {
		return err
	}

	managedIDs := make(map[string]struct{})
	for _, rec := range stored {
		if rec.Site == site && rec.Mode == "zone" {
			managedIDs[rec.UnifiID] = struct{}{}
		}
	}

	zoneMap := make(map[string]string)
	for _, pair := range zm.cfg.ZonePairs {
		// For UDM Pro Max 10.x, zone names cannot be auto-resolved.
		// Zone IDs must be 24-char hex ObjectIDs passed directly via ZONE_PAIRS.
		srcZoneID, err := zm.ctrl.GetZoneID(ctx, site, pair.Src)
		if err != nil {
			return fmt.Errorf("resolve source zone %q for reorder: %w", pair.Src, err)
		}
		dstZoneID, err := zm.ctrl.GetZoneID(ctx, site, pair.Dst)
		if err != nil {
			return fmt.Errorf("resolve destination zone %q for reorder: %w", pair.Dst, err)
		}
		zoneMap[pair.Src] = srcZoneID
		zoneMap[pair.Dst] = dstZoneID
	}

	// Reorder per zone-pair
	for _, pair := range zm.cfg.ZonePairs {
		srcZoneID := zoneMap[pair.Src]
		dstZoneID := zoneMap[pair.Dst]

		// Filter policies for this zone-pair
		var bouncerIDs []string
		for _, p := range allPolicies {
			if p.SrcZone == srcZoneID && p.DstZone == dstZoneID {
				if _, ok := managedIDs[p.ID]; ok {
					bouncerIDs = append(bouncerIDs, p.ID)
				}
			}
		}

		if len(bouncerIDs) == 0 {
			continue // nothing to reorder for this pair
		}

		// Reorder so bouncer policies are evaluated before system-defined policies.
		req := controller.ZonePolicyReorderRequest{
			SourceZoneID:           srcZoneID,
			DestinationZoneID:      dstZoneID,
			BeforeSystemDefinedIDs: bouncerIDs,
		}
		if err := zm.ctrl.ReorderZonePolicies(ctx, site, req); err != nil {
			return fmt.Errorf("reorder zone-pair %s->%s: %w", pair.Src, pair.Dst, err)
		}
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

// UpdateGroupReference updates zone policies that reference an old firewall group ID with a new one.
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

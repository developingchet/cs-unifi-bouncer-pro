package firewall

import (
	"context"
	"fmt"
	"sort"
	"strings"

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

// EnsurePolicies idempotently creates zone policies for each shard and zone pair.
func (zm *ZoneManager) EnsurePolicies(ctx context.Context, site string, v4Shards, v6Shards *ShardManager) error {
	for _, pair := range zm.cfg.ZonePairs {
		if err := zm.ensurePoliciesForPair(ctx, site, pair, false, v4Shards); err != nil {
			return err
		}
		if v6Shards != nil {
			if err := zm.ensurePoliciesForPair(ctx, site, pair, true, v6Shards); err != nil {
				return err
			}
		}
	}
	return nil
}

func (zm *ZoneManager) ensurePoliciesForPair(ctx context.Context, site string, pair config.ZonePair, ipv6 bool, sm *ShardManager) error {
	family := Family(ipv6)
	ipVersion := "IPV4"
	if ipv6 {
		ipVersion = "IPV6"
	}

	groupIDs := sm.GroupIDs()
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
				zm.log.Debug().Str("policy", policyName).Msg("zone policy already exists")
				continue
			}
		}

		policy := controller.ZonePolicy{
			Name:        policyName,
			Enabled:     true,
			Action:      "BLOCK",
			Description: zm.cfg.Description,
			SrcZone:     pair.Src,
			DstZone:     pair.Dst,
			IPVersion:   ipVersion,
			MatchIPs: []controller.MatchSet{
				{FirewallGroupID: groupID, Negate: false},
			},
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

	// Reorder if configured
	if zm.cfg.PolicyReorder {
		if err := zm.reorderPolicies(ctx, site); err != nil {
			zm.log.Warn().Err(err).Str("site", site).Msg("policy reorder failed")
		}
	}

	return nil
}

// reorderPolicies moves all bouncer-managed policies to the top.
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

	var bouncerIDs, otherIDs []string
	for _, p := range allPolicies {
		if _, ok := managedIDs[p.ID]; ok {
			bouncerIDs = append(bouncerIDs, p.ID)
		} else {
			otherIDs = append(otherIDs, p.ID)
		}
	}
	sort.Strings(bouncerIDs)

	orderedIDs := append(bouncerIDs, otherIDs...)
	return zm.ctrl.ReorderZonePolicies(ctx, site, orderedIDs)
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

// UpdateGroupReference updates zone policies that reference an old group ID with a new one.
func (zm *ZoneManager) UpdateGroupReference(ctx context.Context, site, oldGroupID, newGroupID string) error {
	policies, err := zm.ctrl.ListZonePolicies(ctx, site)
	if err != nil {
		return err
	}
	for _, p := range policies {
		needsUpdate := false
		for i, m := range p.MatchIPs {
			if m.FirewallGroupID == oldGroupID {
				p.MatchIPs[i].FirewallGroupID = newGroupID
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

// parseConnectionState normalizes connection state strings.
func parseConnectionState(states []string) string {
	normalized := make([]string, 0, len(states))
	for _, s := range states {
		normalized = append(normalized, strings.ToUpper(strings.TrimSpace(s)))
	}
	return strings.Join(normalized, ",")
}

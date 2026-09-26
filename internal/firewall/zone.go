package firewall

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/rs/zerolog"
)

// ZoneConfig holds configuration for zone-based firewall mode.
type ZoneConfig struct {
	ZonePairs        []config.ZonePair
	Description      string
	LogDrops         bool
	ConnectionStates []string
	APIWriteDelay    time.Duration
}

// ZoneManager manages zone-based firewall policies.
type ZoneManager struct {
	cfg   ZoneConfig
	namer *Namer
	ctrl  controller.Controller
	store storage.Store
	log   zerolog.Logger
	opMu  sync.Mutex // serialize config reload with policy operations

	mu           sync.RWMutex
	zoneCache    map[string]map[string]string     // site -> zone name -> zone ID
	portTMLCache map[string]map[string]portTMLIDs // site -> "SrcName:DstName" -> port TML IDs
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
	zm.opMu.Lock()
	defer zm.opMu.Unlock()
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
		if err := validateZoneNetworks(site, zm.cfg.ZonePairs, zones); err != nil {
			return err
		}

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

		// Ensure port TMLs for zone pairs that have port filters configured.
		sitePortTMLs, err := zm.ensurePortTMLs(ctx, site, zm.cfg.ZonePairs)
		if err != nil {
			return fmt.Errorf("ensure port TMLs for site %q: %w", site, err)
		}

		zm.mu.Lock()
		if zm.zoneCache == nil {
			zm.zoneCache = make(map[string]map[string]string)
		}
		if zm.portTMLCache == nil {
			zm.portTMLCache = make(map[string]map[string]portTMLIDs)
		}
		zm.zoneCache[site] = siteZones
		zm.portTMLCache[site] = sitePortTMLs
		zm.mu.Unlock()
	}
	return nil
}

// Reload updates the zone pair configuration and repopulates the zone ID cache
// for all given sites. All zone IDs are resolved into a staging map first; the
// live cache is updated only if every zone resolves successfully (validate-then-commit).
// Safe to call concurrently with read operations.
func (zm *ZoneManager) Reload(ctx context.Context, sites []string, pairs []config.ZonePair) error {
	zm.opMu.Lock()
	defer zm.opMu.Unlock()
	// Stage all resolutions before acquiring the write lock.
	staged := make(map[string]map[string]string, len(sites))
	stagedPorts := make(map[string]map[string]portTMLIDs, len(sites))

	for _, site := range sites {
		// 1A: Evict stale cache entries so GetZoneID hits the API.
		zm.ctrl.InvalidateZoneCache(site)
		zones, err := zm.ctrl.DiscoverZones(ctx, site)
		if err != nil {
			return fmt.Errorf("discover firewall zones for site %q: %w", site, err)
		}
		if err := validateZoneNetworks(site, pairs, zones); err != nil {
			return err
		}

		siteZones := make(map[string]string)
		for _, pair := range pairs {
			for _, name := range []string{pair.Src, pair.Dst} {
				if _, ok := siteZones[name]; ok {
					continue
				}
				id, err := zm.ctrl.GetZoneID(ctx, site, name)
				if err != nil {
					zm.log.Warn().Err(err).Str("site", site).Str("zone", name).
						Msg("reload: failed to resolve zone ID; aborting update for this site")
					return fmt.Errorf("reload zone %q for site %q: %w", name, site, err)
				}
				siteZones[name] = id
			}
		}

		staged[site] = siteZones
	}
	for _, site := range sites {
		ports, err := zm.ensurePortTMLs(ctx, site, pairs)
		if err != nil {
			return fmt.Errorf("reload port and destination IP filters for site %q: %w", site, err)
		}
		stagedPorts[site] = ports
	}

	// Commit validated sites atomically.
	if len(staged) > 0 {
		zm.mu.Lock()
		if zm.zoneCache == nil {
			zm.zoneCache = make(map[string]map[string]string)
		}
		if zm.portTMLCache == nil {
			zm.portTMLCache = make(map[string]map[string]portTMLIDs)
		}
		for site, siteZones := range staged {
			zm.zoneCache[site] = siteZones
			zm.portTMLCache[site] = stagedPorts[site]
		}
		zm.cfg.ZonePairs = pairs
		zm.mu.Unlock()
	}

	return nil
}

func validateZoneNetworks(site string, pairs []config.ZonePair, zones []controller.Zone) error {
	used := make(map[string]bool, len(pairs)*2)
	for _, pair := range pairs {
		used[pair.Src] = true
		used[pair.Dst] = true
	}
	for _, zone := range zones {
		if !used[zone.Name] || zone.NetworkIDs == nil {
			continue
		}
		if strings.EqualFold(zone.Name, "External") || strings.EqualFold(zone.Name, "Gateway") {
			continue
		}
		if len(zone.NetworkIDs) == 0 {
			return fmt.Errorf("configured firewall zone %q at site %q has no networks", zone.Name, site)
		}
	}
	return nil
}

// zoneMapForSite returns the cached zone name -> ID map for site, having
// verified that every configured zone pair's src/dst zones are present in it.
func (zm *ZoneManager) zoneMapForSite(site string) (map[string]string, error) {
	zm.mu.RLock()
	zoneMap, ok := zm.zoneCache[site]
	zm.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("zone cache not populated for site %q — was Bootstrap called?", site)
	}
	for _, pair := range zm.cfg.ZonePairs {
		if _, ok := zoneMap[pair.Src]; !ok {
			return nil, fmt.Errorf("zone %q not in cache for site %q", pair.Src, site)
		}
		if _, ok := zoneMap[pair.Dst]; !ok {
			return nil, fmt.Errorf("zone %q not in cache for site %q", pair.Dst, site)
		}
	}
	return zoneMap, nil
}

// cleanupOrphanedBlockPolicies deletes block zone policies whose names are no
// longer in expectedNames — meaning the zone pair they belong to was removed
// from config. Two complementary sweeps are performed:
//
//   - bbolt sweep: removes policies tracked in bbolt (mode "zone") that are no
//     longer expected. Cleans both the API object and the bbolt record.
//   - API sweep: removes block policies with the managed description and name
//     prefix that are not in expectedNames, even without a bbolt record.
func (zm *ZoneManager) cleanupOrphanedBlockPolicies(ctx context.Context, site string, expectedNames map[string]bool, existingByID map[string]controller.ZonePolicy) error {
	deletedIDs := make(map[string]bool)
	var cleanupErrors []error

	// Pass 1 — bbolt-based: handles the normal case where bbolt tracks the policy.
	allBbolt, err := zm.store.ListPolicies()
	if err != nil {
		zm.log.Warn().Err(err).Str("site", site).Msg("orphan cleanup: failed to list bbolt policies")
	} else {
		for key, rec := range allBbolt {
			if rec.Site != site || rec.Mode != "zone" {
				continue
			}
			name := cacheName(key)
			if expectedNames[name] {
				continue
			}
			// Orphan: in bbolt for this site but not expected by current config.
			if p, exists := existingByID[rec.UnifiID]; exists && p.Name == name && p.Action == "BLOCK" {
				if delErr := zm.ctrl.DeleteZonePolicy(ctx, site, rec.UnifiID); delErr != nil {
					zm.log.Warn().Err(delErr).Str("policy", name).Msg("failed to delete orphaned zone policy")
					cleanupErrors = append(cleanupErrors, fmt.Errorf("delete orphaned zone policy %s: %w", name, delErr))
					continue
				} else {
					zm.log.Info().Str("policy", name).Str("site", site).
						Msg("deleted orphaned zone policy (zone pair removed from config)")
					deletedIDs[rec.UnifiID] = true
				}
			}
			// Keep the cache record if deletion failed so the next reconcile retries it.
			if delErr := zm.store.DeletePolicy(key); delErr != nil {
				zm.log.Warn().Err(delErr).Str("policy", name).Msg("failed to remove orphaned policy from bbolt")
			}
		}
	}

	// Pass 2 — API-based: catches orphans that have no bbolt record (wiped bbolt,
	// prior bouncer version, or leftover from a mode switch).
	// Guards: description AND action must match what the bouncer creates — this
	// ensures a user-created ALLOW/REJECT policy with our description is never touched.
	for id, p := range existingByID {
		if deletedIDs[id] {
			continue // already handled in pass 1
		}
		if p.Description != zm.cfg.Description {
			continue
		}
		if prefix := zm.namer.PolicyPrefix(); prefix == "" || !strings.HasPrefix(p.Name, prefix) {
			continue // without a bbolt record, description alone does not prove ownership
		}
		if p.Action != "BLOCK" {
			continue // the block manager only ever creates BLOCK zone policies
		}
		if expectedNames[p.Name] {
			continue
		}
		if delErr := zm.ctrl.DeleteZonePolicy(ctx, site, id); delErr != nil {
			zm.log.Warn().Err(delErr).Str("policy", p.Name).Str("site", site).
				Msg("failed to delete API-orphaned zone policy")
			cleanupErrors = append(cleanupErrors, fmt.Errorf("delete API-orphaned zone policy %s: %w", p.Name, delErr))
			continue
		} else {
			zm.log.Info().Str("policy", p.Name).Str("site", site).
				Msg("deleted API-orphaned zone policy (matches managed description, not in current config)")
		}
		// Clean up any stale bbolt entry that may exist under this name.
		_ = deleteCachedPolicy(zm.store, site, p.Name)
	}
	return errors.Join(cleanupErrors...)
}

// DeletePoliciesForShard deletes all zone policies for the given shard across all zone pairs.
// Called during shard pruning.
func (zm *ZoneManager) DeletePoliciesForShard(ctx context.Context, site string, ipv6 bool, shardIdx int) error {
	zm.opMu.Lock()
	defer zm.opMu.Unlock()
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

		existing, lookupErr := getCachedPolicy(zm.store, site, policyName)
		if lookupErr != nil {
			return fmt.Errorf("lookup policy %s: %w", policyName, lookupErr)
		}

		if existing == nil || existing.UnifiID == "" {
			continue // Already gone
		}

		if err := zm.ctrl.DeleteZonePolicy(ctx, site, existing.UnifiID); err != nil {
			return fmt.Errorf("delete zone policy %s: %w", policyName, err)
		}

		if err := deleteCachedPolicy(zm.store, site, policyName); err != nil {
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
	var errs []error
	for name, rec := range policies {
		if rec.Site != site || rec.Mode != "zone" {
			continue
		}
		if err := zm.ctrl.DeleteZonePolicy(ctx, site, rec.UnifiID); err != nil {
			var missing *controller.ErrNotFound
			if !errors.As(err, &missing) {
				errs = append(errs, fmt.Errorf("delete zone policy %s: %w", name, err))
				continue
			}
		}
		if err := zm.store.DeletePolicy(name); err != nil {
			errs = append(errs, fmt.Errorf("remove zone policy %s from storage: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

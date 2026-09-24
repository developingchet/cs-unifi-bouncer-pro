package firewall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
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

// portTMLIDs holds TML IDs for a single zone pair (port filters and dst IP filter).
type portTMLIDs struct {
	SrcTMLID    string   // empty if no src port filter configured
	DstTMLID    string   // empty if no dst port filter configured
	DstIPTMLIDs []string // ordered: v4 TML first (if present), v6 TML second; use pickDstIPTML to select
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

// ensurePortTMLs creates or reuses port TMLs and dst IP TMLs for all zone pairs
// that have port or IP filters configured. Returns a map of "SrcName:DstName" -> portTMLIDs.
func (zm *ZoneManager) ensurePortTMLs(ctx context.Context, site string, pairs []config.ZonePair) (map[string]portTMLIDs, error) {
	result := make(map[string]portTMLIDs)

	// Check whether any pair needs TMLs of any kind.
	needsTMLs := false
	for _, pair := range pairs {
		if len(pair.SrcPorts) > 0 || len(pair.DstPorts) > 0 || len(pair.DstIPs) > 0 {
			needsTMLs = true
			break
		}
	}
	if !needsTMLs {
		return result, nil
	}

	// Fetch existing TMLs once for idempotency.
	existing, err := zm.ctrl.ListTrafficMatchingLists(ctx, site)
	if err != nil {
		return nil, fmt.Errorf("list TMLs: %w", err)
	}
	existingByName := make(map[string]controller.TrafficMatchingList, len(existing))
	for _, t := range existing {
		existingByName[t.Name] = t
	}

	for _, pair := range pairs {
		key := pair.Src + ":" + pair.Dst
		ids := portTMLIDs{}

		if len(pair.SrcPorts) > 0 {
			name := "crowdsec-ports-src-" + pair.Src + "-" + pair.Dst
			id, err := zm.ensurePortTML(ctx, site, name, pair.SrcPorts, existingByName)
			if err != nil {
				return nil, fmt.Errorf("ensure src port TML %q: %w", name, err)
			}
			ids.SrcTMLID = id
		}
		if len(pair.DstPorts) > 0 {
			name := "crowdsec-ports-dst-" + pair.Src + "-" + pair.Dst
			id, err := zm.ensurePortTML(ctx, site, name, pair.DstPorts, existingByName)
			if err != nil {
				return nil, fmt.Errorf("ensure dst port TML %q: %w", name, err)
			}
			ids.DstTMLID = id
		}
		if len(pair.DstIPs) > 0 {
			v4IPs, v6IPs := classifyIPs(pair.DstIPs)
			if len(v4IPs) > 0 {
				name := "crowdsec-dstips-v4-" + pair.Src + "-" + pair.Dst
				id, err := zm.ensureIPTML(ctx, site, name, "IPV4_ADDRESSES", v4IPs, existingByName)
				if err != nil {
					return nil, fmt.Errorf("ensure dst IPv4 TML %q: %w", name, err)
				}
				ids.DstIPTMLIDs = append(ids.DstIPTMLIDs, id)
			}
			if len(v6IPs) > 0 {
				name := "crowdsec-dstips-v6-" + pair.Src + "-" + pair.Dst
				id, err := zm.ensureIPTML(ctx, site, name, "IPV6_ADDRESSES", v6IPs, existingByName)
				if err != nil {
					return nil, fmt.Errorf("ensure dst IPv6 TML %q: %w", name, err)
				}
				ids.DstIPTMLIDs = append(ids.DstIPTMLIDs, id)
			}
		}
		result[key] = ids
	}
	return result, nil
}

// ensurePortTML creates a PORTS TML without changing a list referenced by an
// active policy. On filter changes it creates a content-versioned list first.
func (zm *ZoneManager) ensurePortTML(ctx context.Context, site, name string, ports []int, existingByName map[string]controller.TrafficMatchingList) (string, error) {
	items := make([]controller.TrafficMatchingListItem, 0, len(ports))
	for _, p := range ports {
		items = append(items, controller.TrafficMatchingListItem{Type: "PORT_NUMBER", Value: strconv.Itoa(p)})
	}

	return zm.ensureImmutableFilterTML(ctx, site, name, "PORTS", items, existingByName)
}

// ensureIPTML creates an IP-address TML without mutating an active filter.
func (zm *ZoneManager) ensureIPTML(ctx context.Context, site, name, tmlType string, ips []string, existingByName map[string]controller.TrafficMatchingList) (string, error) {
	items := make([]controller.TrafficMatchingListItem, 0, len(ips))
	for _, ip := range ips {
		itemType := "IP_ADDRESS"
		if strings.Contains(ip, "/") {
			itemType = "SUBNET"
		}
		items = append(items, controller.TrafficMatchingListItem{Type: itemType, Value: ip})
	}

	return zm.ensureImmutableFilterTML(ctx, site, name, tmlType, items, existingByName)
}

func (zm *ZoneManager) ensureImmutableFilterTML(ctx context.Context, site, baseName, tmlType string, items []controller.TrafficMatchingListItem, existingByName map[string]controller.TrafficMatchingList) (string, error) {
	if found, ok := existingByName[baseName]; ok && found.Type == tmlType && tmlItemsMatch(found.Items, items) {
		return found.ID, nil
	}
	values := make([]string, 0, len(items))
	for _, item := range items {
		values = append(values, item.Type+":"+item.Value)
	}
	sort.Strings(values)
	digest := sha256.Sum256([]byte(tmlType + ":" + strings.Join(values, ",")))
	versionedName := baseName + "-" + hex.EncodeToString(digest[:6])
	if found, ok := existingByName[versionedName]; ok {
		if found.Type != tmlType || !tmlItemsMatch(found.Items, items) {
			return "", fmt.Errorf("filter TML %s has unexpected contents", versionedName)
		}
		return found.ID, nil
	}
	name := baseName
	if _, exists := existingByName[baseName]; exists {
		name = versionedName
	}
	created, err := zm.ctrl.CreateTrafficMatchingList(ctx, site, controller.TrafficMatchingList{Name: name, Type: tmlType, Items: items})
	if err != nil {
		return "", fmt.Errorf("create filter TML %s: %w", name, err)
	}
	existingByName[name] = created
	zm.log.Info().Str("tml", name).Str("id", created.ID).Int("items", len(items)).Msg("created filter TML")
	return created.ID, nil
}

func tmlItemsMatch(existing, desired []controller.TrafficMatchingListItem) bool {
	if len(existing) != len(desired) {
		return false
	}
	counts := make(map[string]int, len(existing))
	for _, item := range existing {
		counts[item.Type+":"+item.Value]++
	}
	for _, item := range desired {
		key := item.Type + ":" + item.Value
		counts[key]--
		if counts[key] < 0 {
			return false
		}
	}
	return true
}

// pickDstIPTML selects the destination IP TML ID for a policy.
//
// ids is the DstIPTMLIDs slice from portTMLIDs — ordered v4 first (if present),
// v6 second (if present). Selection rule:
//
//	len 0 → ""             no destination IP filter configured
//	len 1 → ids[0]         single-family: both v4 and v6 policies share the same TML
//	len 2 → ids[1] if ipv6 mixed: each policy uses the TML whose family matches (API ceiling)
//	         ids[0] otherwise
//
// This keeps the destination filter family-agnostic: a v4-only dst IP is applied
// to the v6 block policy as well (and vice versa), scoping both address families
// to the same destination host.
func pickDstIPTML(ids []string, ipv6 bool) string {
	switch len(ids) {
	case 0:
		return ""
	case 1:
		return ids[0]
	default: // len >= 2: mixed; use the family-matching TML
		if ipv6 {
			return ids[1]
		}
		return ids[0]
	}
}

// classifyIPs splits a list of IPs/CIDRs into IPv4 and IPv6 groups.
func classifyIPs(ips []string) (v4, v6 []string) {
	for _, ip := range ips {
		addr := ip
		if idx := strings.Index(ip, "/"); idx != -1 {
			addr = ip[:idx]
		}
		if parsed := net.ParseIP(addr); parsed != nil && parsed.To4() != nil {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}
	return
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

// EnsurePolicies idempotently creates zone policies for each shard and zone pair.
func (zm *ZoneManager) EnsurePolicies(ctx context.Context, site string, v4Shards, v6Shards *ShardManager) error {
	zm.opMu.Lock()
	defer zm.opMu.Unlock()
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

	// Build the set of all policy names expected by the current config so that
	// cleanupOrphanedBlockPolicies can identify policies from removed zone pairs.
	expectedNames := make(map[string]bool)
	for _, pair := range zm.cfg.ZonePairs {
		for _, ipv6 := range []bool{false, true} {
			sm := v4Shards
			if ipv6 {
				sm = v6Shards
			}
			if sm == nil {
				continue
			}
			family := Family(ipv6)
			for _, ref := range sm.GroupRefs() {
				name, err := zm.namer.PolicyName(NameData{
					Family:  family,
					Index:   ref.Index,
					Site:    site,
					SrcZone: pair.Src,
					DstZone: pair.Dst,
				})
				if err == nil {
					expectedNames[name] = true
				}
			}
		}
	}

	for _, pair := range zm.cfg.ZonePairs {
		if err := zm.ensurePoliciesForPair(ctx, site, pair, zoneMap, existingByID, false, v4Shards); err != nil {
			return err
		}
		if v6Shards != nil {
			if err := zm.ensurePoliciesForPair(ctx, site, pair, zoneMap, existingByID, true, v6Shards); err != nil {
				return err
			}
		}
	}

	// Remove any block policies that were managed by this bouncer but whose
	// zone pair has since been removed from ZONE_PAIRS config.
	if err := zm.cleanupOrphanedBlockPolicies(ctx, site, expectedNames, existingByID); err != nil {
		return err
	}
	zm.mu.RLock()
	portIDs := zm.portTMLCache[site]
	zm.mu.RUnlock()
	zm.cleanupOrphanedPortTMLs(ctx, site, portIDs)
	return nil
}

func (zm *ZoneManager) ensurePoliciesForPair(ctx context.Context, site string, pair config.ZonePair, zoneMap map[string]string, existingByID map[string]controller.ZonePolicy, ipv6 bool, sm *ShardManager) error {
	family := Family(ipv6)
	ipVersion := "IPV4"
	if ipv6 {
		ipVersion = "IPV6"
	}

	groupRefs := sm.GroupRefs()
	srcZoneID := zoneMap[pair.Src]
	dstZoneID := zoneMap[pair.Dst]

	// Look up port TML IDs and dst IP TML ID for this pair.
	zm.mu.RLock()
	var srcPortTMLID, dstPortTMLID, dstIPTMLID string
	if sitePortTMLs, ok := zm.portTMLCache[site]; ok {
		if ids, ok := sitePortTMLs[pair.Src+":"+pair.Dst]; ok {
			srcPortTMLID = ids.SrcTMLID
			dstPortTMLID = ids.DstTMLID
			dstIPTMLID = pickDstIPTML(ids.DstIPTMLIDs, ipv6)
		}
	}
	zm.mu.RUnlock()

	firstCreate := true
	for _, ref := range groupRefs {
		i, groupID := ref.Index, ref.ID
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
			ConnectionStateFilter:  append([]string(nil), zm.cfg.ConnectionStates...),
			LoggingEnabled:         zm.cfg.LogDrops,
			SrcPortTMLID:           srcPortTMLID,
			DstPortTMLID:           dstPortTMLID,
			DstIPTMLID:             dstIPTMLID,
		}

		existing, lookupErr := getCachedPolicy(zm.store, site, policyName)
		if lookupErr != nil {
			return fmt.Errorf("lookup policy %s: %w", policyName, lookupErr)
		}
		if existing == nil || existing.UnifiID == "" || existingByID[existing.UnifiID].ID == "" {
			for _, candidate := range existingByID {
				if candidate.Name != policyName {
					continue
				}
				if candidate.Description != zm.cfg.Description {
					return fmt.Errorf("policy %s exists with a different description", policyName)
				}
				if err := setCachedPolicy(zm.store, site, policyName, storage.PolicyRecord{UnifiID: candidate.ID, Site: site, Mode: "zone"}); err != nil {
					return fmt.Errorf("cache existing zone policy %s: %w", policyName, err)
				}
				existing = &storage.PolicyRecord{UnifiID: candidate.ID, Site: site, Mode: "zone"}
				break
			}
		}

		// Check if policy exists in API and needs update (reconcile mode)
		if existing != nil && existing.UnifiID != "" {
			if apiPolicy, found := existingByID[existing.UnifiID]; found {
				if apiPolicy.Name != policyName {
					return fmt.Errorf("cached policy %s points to different API policy %s", policyName, apiPolicy.Name)
				}
				if needsUpdateZonePolicy(&apiPolicy, groupID, srcPortTMLID, dstPortTMLID, dstIPTMLID, srcZoneID, dstZoneID, ipVersion, zm.cfg.Description, zm.cfg.ConnectionStates, zm.cfg.LogDrops) {
					zm.log.Info().Str("policy", policyName).Msg("zone policy needs update, applying reconcile")

					// The UniFi PUT endpoint cannot change port and destination-IP filters.
					// Create a staged replacement first so a failed delete or rename
					// never leaves this shard without a block policy.
					portFilterChanging := apiPolicy.SrcPortTMLID != srcPortTMLID || apiPolicy.DstPortTMLID != dstPortTMLID || apiPolicy.DstIPTMLID != dstIPTMLID
					if portFilterChanging {
						staged, stageErr := zm.stageReplacementPolicy(ctx, site, policy, existingByID)
						if stageErr != nil {
							return fmt.Errorf("stage replacement for zone policy %s: %w", policyName, stageErr)
						}
						if delErr := zm.ctrl.DeleteZonePolicy(ctx, site, existing.UnifiID); delErr != nil {
							var nf *controller.ErrNotFound
							if !errors.As(delErr, &nf) {
								return fmt.Errorf("delete old zone policy %s after staging replacement: %w", policyName, delErr)
							}
						}
						delete(existingByID, existing.UnifiID)
						policy.ID = staged.ID
						if err := zm.ctrl.UpdateZonePolicy(ctx, site, policy); err != nil {
							return fmt.Errorf("rename staged zone policy %s: %w", policyName, err)
						}
						if err := setCachedPolicy(zm.store, site, policyName, storage.PolicyRecord{UnifiID: staged.ID, Site: site, Mode: "zone"}); err != nil {
							return fmt.Errorf("cache replacement zone policy %s: %w", policyName, err)
						}
						existingByID[staged.ID] = policy
						continue
					} else {
						updateErr := zm.updateZonePolicy(ctx, site, apiPolicy, groupID, srcPortTMLID, dstPortTMLID, dstIPTMLID, srcZoneID, dstZoneID, ipVersion)
						if updateErr != nil {
							var nf *controller.ErrNotFound
							if !errors.As(updateErr, &nf) {
								return fmt.Errorf("update zone policy %s: %w", policyName, updateErr)
							}
							// 404 on PUT: policy was externally deleted; clear bbolt and fall through to create.
							zm.log.Warn().Str("policy", policyName).Str("id", existing.UnifiID).
								Msg("zone policy not found on update (externally deleted?); clearing record for re-creation")
							_ = deleteCachedPolicy(zm.store, site, policyName)
						} else {
							continue
						}
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

		created, err := zm.ctrl.CreateZonePolicy(ctx, site, policy)
		if err != nil {
			var conflict *controller.ErrConflict
			if errors.As(err, &conflict) {
				if id := zm.findExistingPolicyByName(ctx, site, policyName); id != "" {
					zm.log.Warn().Str("policy", policyName).Str("id", id).
						Msg("zone policy already exists (409 conflict); recovering existing ID")
					if storeErr := setCachedPolicy(zm.store, site, policyName, storage.PolicyRecord{UnifiID: id, Site: site, Mode: "zone"}); storeErr != nil {
						zm.log.Warn().Err(storeErr).Str("policy", policyName).Msg("failed to cache recovered policy in bbolt")
					}
					existingByID[id] = controller.ZonePolicy{ID: id}
					continue
				}
			}
			return fmt.Errorf("create zone policy %s: %w", policyName, err)
		}
		existingByID[created.ID] = created

		if err := setCachedPolicy(zm.store, site, policyName, storage.PolicyRecord{
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

// stageReplacementPolicy provisions the desired filters under a temporary
// managed name before the old policy is removed. A retry reuses an existing
// stage only when it still targets the same group and filters.
func (zm *ZoneManager) stageReplacementPolicy(ctx context.Context, site string, desired controller.ZonePolicy, existingByID map[string]controller.ZonePolicy) (controller.ZonePolicy, error) {
	parts := []string{desired.Name, desired.SrcZone, desired.DstZone, desired.IPVersion,
		desired.TrafficMatchingListIDs[0], desired.SrcPortTMLID, desired.DstPortTMLID, desired.DstIPTMLID}
	digest := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	stagedName := "crowdsec-policy-stage-" + hex.EncodeToString(digest[:10])
	stagedDesired := desired
	stagedDesired.Name = stagedName
	reuse := func(candidate controller.ZonePolicy) (controller.ZonePolicy, error) {
		if len(candidate.TrafficMatchingListIDs) != 1 || candidate.TrafficMatchingListIDs[0] != desired.TrafficMatchingListIDs[0] ||
			candidate.SrcPortTMLID != desired.SrcPortTMLID || candidate.DstPortTMLID != desired.DstPortTMLID || candidate.DstIPTMLID != desired.DstIPTMLID {
			return controller.ZonePolicy{}, fmt.Errorf("staged policy %s has unexpected group or filter IDs", stagedName)
		}
		if needsUpdateZonePolicy(&candidate, desired.TrafficMatchingListIDs[0], desired.SrcPortTMLID, desired.DstPortTMLID,
			desired.DstIPTMLID, desired.SrcZone, desired.DstZone, desired.IPVersion, desired.Description,
			desired.ConnectionStateFilter, desired.LoggingEnabled) {
			stagedDesired.ID = candidate.ID
			if err := zm.ctrl.UpdateZonePolicy(ctx, site, stagedDesired); err != nil {
				return controller.ZonePolicy{}, fmt.Errorf("repair staged policy %s: %w", stagedName, err)
			}
		}
		return candidate, nil
	}
	for _, candidate := range existingByID {
		if candidate.Name == stagedName {
			return reuse(candidate)
		}
	}
	staged, err := zm.ctrl.CreateZonePolicy(ctx, site, stagedDesired)
	if err == nil {
		return staged, nil
	}
	var conflict *controller.ErrConflict
	if !errors.As(err, &conflict) {
		return controller.ZonePolicy{}, fmt.Errorf("create staged policy %s: %w", stagedName, err)
	}
	policies, listErr := zm.ctrl.ListZonePolicies(ctx, site)
	if listErr != nil {
		return controller.ZonePolicy{}, fmt.Errorf("find staged policy %s: %w", stagedName, listErr)
	}
	for _, candidate := range policies {
		if candidate.Name == stagedName {
			return reuse(candidate)
		}
	}
	return controller.ZonePolicy{}, fmt.Errorf("staged policy %s conflicted but was not found", stagedName)
}

// EnsurePoliciesForShard creates zone policies for a single new shard across all configured zone pairs.
// Called when a new shard overflows mid-operation.
func (zm *ZoneManager) EnsurePoliciesForShard(ctx context.Context, site, groupID string, ipv6 bool, shardIdx int) error {
	zm.opMu.Lock()
	defer zm.opMu.Unlock()
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

		existing, lookupErr := getCachedPolicy(zm.store, site, policyName)
		if lookupErr != nil {
			return fmt.Errorf("lookup policy %s: %w", policyName, lookupErr)
		}

		if existing != nil && existing.UnifiID != "" && existingByUnifiID[existing.UnifiID] {
			zm.log.Debug().Str("policy", policyName).Msg("zone policy already exists for new shard")
			continue
		}

		srcZoneID := zoneMap[pair.Src]
		dstZoneID := zoneMap[pair.Dst]

		// Look up port TML IDs and dst IP TML ID for this pair.
		var srcPortTMLID, dstPortTMLID, dstIPTMLID string
		zm.mu.RLock()
		if sitePortTMLs, ok := zm.portTMLCache[site]; ok {
			if ids, ok := sitePortTMLs[pair.Src+":"+pair.Dst]; ok {
				srcPortTMLID = ids.SrcTMLID
				dstPortTMLID = ids.DstTMLID
				dstIPTMLID = pickDstIPTML(ids.DstIPTMLIDs, ipv6)
			}
		}
		zm.mu.RUnlock()

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
			ConnectionStateFilter:  append([]string(nil), zm.cfg.ConnectionStates...),
			LoggingEnabled:         zm.cfg.LogDrops,
			SrcPortTMLID:           srcPortTMLID,
			DstPortTMLID:           dstPortTMLID,
			DstIPTMLID:             dstIPTMLID,
		}

		created, err := zm.ctrl.CreateZonePolicy(ctx, site, policy)
		if err != nil {
			var conflict *controller.ErrConflict
			if errors.As(err, &conflict) {
				if id := zm.findExistingPolicyByName(ctx, site, policyName); id != "" {
					zm.log.Warn().Str("policy", policyName).Str("id", id).
						Msg("zone policy already exists (409 conflict); recovering existing ID")
					if storeErr := setCachedPolicy(zm.store, site, policyName, storage.PolicyRecord{UnifiID: id, Site: site, Mode: "zone"}); storeErr != nil {
						zm.log.Warn().Err(storeErr).Str("policy", policyName).Msg("failed to cache recovered policy in bbolt")
					}
					continue
				}
			}
			return fmt.Errorf("create zone policy %s: %w", policyName, err)
		}

		if err := setCachedPolicy(zm.store, site, policyName, storage.PolicyRecord{
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

// cleanupOrphanedPortTMLs removes filter lists no longer referenced by the
// current pair configuration. IDs handle both base and content-versioned names.
func (zm *ZoneManager) cleanupOrphanedPortTMLs(ctx context.Context, site string, sitePortTMLs map[string]portTMLIDs) {
	expectedIDs := make(map[string]bool, len(sitePortTMLs)*4)
	for _, ids := range sitePortTMLs {
		for _, id := range append([]string{ids.SrcTMLID, ids.DstTMLID}, ids.DstIPTMLIDs...) {
			if id != "" {
				expectedIDs[id] = true
			}
		}
	}

	allTMLs, err := zm.ctrl.ListTrafficMatchingLists(ctx, site)
	if err != nil {
		zm.log.Warn().Err(err).Str("site", site).Msg("orphan port TML cleanup: failed to list TMLs")
		return
	}
	for _, t := range allTMLs {
		if !strings.HasPrefix(t.Name, "crowdsec-ports-src-") &&
			!strings.HasPrefix(t.Name, "crowdsec-ports-dst-") &&
			!strings.HasPrefix(t.Name, "crowdsec-dstips-v4-") &&
			!strings.HasPrefix(t.Name, "crowdsec-dstips-v6-") {
			continue
		}
		if expectedIDs[t.ID] {
			continue
		}
		if delErr := zm.ctrl.DeleteTrafficMatchingList(ctx, site, t.ID); delErr != nil {
			zm.log.Warn().Err(delErr).Str("tml", t.Name).Str("site", site).
				Msg("failed to delete orphaned block port TML")
		} else {
			zm.log.Info().Str("tml", t.Name).Str("site", site).
				Msg("deleted orphaned block port TML (zone pair removed from config)")
		}
	}
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
// It checks:
// 1. ConnectionStateFilter and logging match the desired settings
// 2. TrafficMatchingListIDs is empty or has the wrong IP TML ID
// 3. SrcPortTMLID, DstPortTMLID, or DstIPTMLID differ from desired
func needsUpdateZonePolicy(policy *controller.ZonePolicy, desiredTMLID, desiredSrcPortTMLID, desiredDstPortTMLID, desiredDstIPTMLID, srcZoneID, dstZoneID, ipVersion, description string, states []string, logDrops bool) bool {
	if !policy.Enabled || policy.Action != "BLOCK" || policy.SrcZone != srcZoneID || policy.DstZone != dstZoneID || policy.IPVersion != ipVersion || policy.Description != description {
		return true
	}
	if !sameConnectionStates(policy.ConnectionStateFilter, states) || policy.LoggingEnabled != logDrops {
		return true
	}
	// TrafficMatchingListIDs should have exactly one entry with the desired TML ID
	if len(policy.TrafficMatchingListIDs) != 1 || policy.TrafficMatchingListIDs[0] != desiredTMLID {
		return true
	}
	if policy.SrcPortTMLID != desiredSrcPortTMLID {
		return true
	}
	if policy.DstPortTMLID != desiredDstPortTMLID {
		return true
	}
	if policy.DstIPTMLID != desiredDstIPTMLID {
		return true
	}
	return false
}

func sameConnectionStates(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	counts := make(map[string]int, len(a))
	for _, state := range a {
		counts[state]++
	}
	for _, state := range b {
		counts[state]--
		if counts[state] < 0 {
			return false
		}
	}
	return true
}

// updateZonePolicy updates an existing zone policy with the correct settings.
func (zm *ZoneManager) updateZonePolicy(ctx context.Context, site string, policy controller.ZonePolicy, newGroupID, srcPortTMLID, dstPortTMLID, dstIPTMLID, srcZoneID, dstZoneID, ipVersion string) error {
	policy.Enabled = true
	policy.Action = "BLOCK"
	policy.Description = zm.cfg.Description
	policy.SrcZone = srcZoneID
	policy.DstZone = dstZoneID
	policy.IPVersion = ipVersion
	policy.TrafficMatchingListIDs = []string{newGroupID}
	policy.ConnectionStateFilter = append([]string(nil), zm.cfg.ConnectionStates...)
	policy.LoggingEnabled = zm.cfg.LogDrops
	policy.SrcPortTMLID = srcPortTMLID
	policy.DstPortTMLID = dstPortTMLID
	policy.DstIPTMLID = dstIPTMLID
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

package firewall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"slices"
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

// Name prefixes of the per-pair filter lists. A list is named prefix+"<src>-<dst>".
const (
	filterSrcPortsPrefix = "crowdsec-ports-src-"
	filterDstPortsPrefix = "crowdsec-ports-dst-"
	filterDstIPsV4Prefix = "crowdsec-dstips-v4-"
	filterDstIPsV6Prefix = "crowdsec-dstips-v6-"
)

func filterTMLName(prefix string, pair config.ZonePair) string {
	return prefix + pair.Src + "-" + pair.Dst
}

// isFilterTMLName reports whether name belongs to a per-pair filter list,
// including its content-versioned variants.
func isFilterTMLName(name string) bool {
	for _, prefix := range []string{filterSrcPortsPrefix, filterDstPortsPrefix, filterDstIPsV4Prefix, filterDstIPsV6Prefix} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
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
			name := filterTMLName(filterSrcPortsPrefix, pair)
			id, err := zm.ensurePortTML(ctx, site, name, pair.SrcPorts, existingByName)
			if err != nil {
				return nil, fmt.Errorf("ensure src port TML %q: %w", name, err)
			}
			ids.SrcTMLID = id
		}
		if len(pair.DstPorts) > 0 {
			name := filterTMLName(filterDstPortsPrefix, pair)
			id, err := zm.ensurePortTML(ctx, site, name, pair.DstPorts, existingByName)
			if err != nil {
				return nil, fmt.Errorf("ensure dst port TML %q: %w", name, err)
			}
			ids.DstTMLID = id
		}
		if len(pair.DstIPs) > 0 {
			v4IPs, v6IPs := classifyIPs(pair.DstIPs)
			if len(v4IPs) > 0 {
				name := filterTMLName(filterDstIPsV4Prefix, pair)
				id, err := zm.ensureIPTML(ctx, site, name, "IPV4_ADDRESSES", v4IPs, existingByName)
				if err != nil {
					return nil, fmt.Errorf("ensure dst IPv4 TML %q: %w", name, err)
				}
				ids.DstIPTMLIDs = append(ids.DstIPTMLIDs, id)
			}
			if len(v6IPs) > 0 {
				name := filterTMLName(filterDstIPsV6Prefix, pair)
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
			for _, ref := range sm.OwnedRefs() {
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

	// One shard the controller refuses must not leave every later shard
	// without a policy, so failures are collected and the rest carry on.
	var failed []error
	for _, pair := range zm.cfg.ZonePairs {
		failed = append(failed, zm.ensurePoliciesForPair(ctx, site, pair, zoneMap, existingByID, false, v4Shards)...)
		if v6Shards != nil {
			failed = append(failed, zm.ensurePoliciesForPair(ctx, site, pair, zoneMap, existingByID, true, v6Shards)...)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
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
	return provisionFailure(failed)
}

// ensurePoliciesForPair ensures the block policy of every active shard for one
// zone pair. It returns one error per shard that failed; those shards are
// marked so the next sync retries them.
func (zm *ZoneManager) ensurePoliciesForPair(ctx context.Context, site string, pair config.ZonePair, zoneMap map[string]string, existingByID map[string]controller.ZonePolicy, ipv6 bool, sm *ShardManager) []error {
	var failed []error
	firstCreate := true
	for _, ref := range sm.GroupRefs() {
		if ctx.Err() != nil {
			return failed
		}
		created, err := zm.ensureShardPolicy(ctx, site, pair, zoneMap, existingByID, ipv6, ref, !firstCreate)
		if err != nil {
			sm.MarkUnprovisioned(ref.Index)
			failed = append(failed, fmt.Errorf("%s shard %d (%s->%s): %w", Family(ipv6), ref.Index, pair.Src, pair.Dst, err))
			continue
		}
		if created {
			firstCreate = false
		}
	}
	return failed
}

func (zm *ZoneManager) ensureShardPolicy(ctx context.Context, site string, pair config.ZonePair, zoneMap map[string]string,
	existingByID map[string]controller.ZonePolicy, ipv6 bool, ref GroupRef, delay bool,
) (bool, error) {
	desired, err := zm.desiredPolicy(site, pair, zoneMap, ipv6, ref.Index, ref.ID)
	if err != nil {
		return false, err
	}
	return zm.ensurePolicy(ctx, site, desired, existingByID, delay)
}

// desiredPolicy renders the block policy the bouncer maintains for one shard
// and zone pair.
func (zm *ZoneManager) desiredPolicy(site string, pair config.ZonePair, zoneMap map[string]string, ipv6 bool, shardIdx int, groupID string) (controller.ZonePolicy, error) {
	name, err := zm.namer.PolicyName(NameData{Family: Family(ipv6), Index: shardIdx, Site: site, SrcZone: pair.Src, DstZone: pair.Dst})
	if err != nil {
		return controller.ZonePolicy{}, err
	}
	if groupID == "" {
		return controller.ZonePolicy{}, fmt.Errorf("shard %d for %s->%s has empty TML ID — cannot create block policy without source filter", shardIdx, pair.Src, pair.Dst)
	}
	ipVersion := "IPV4"
	if ipv6 {
		ipVersion = "IPV6"
	}
	policy := controller.ZonePolicy{
		Name:                   name,
		Enabled:                true,
		Action:                 "BLOCK",
		Description:            zm.cfg.Description,
		SrcZone:                zoneMap[pair.Src],
		DstZone:                zoneMap[pair.Dst],
		IPVersion:              ipVersion,
		TrafficMatchingListIDs: []string{groupID},
		ConnectionStateFilter:  append([]string(nil), zm.cfg.ConnectionStates...),
		LoggingEnabled:         zm.cfg.LogDrops,
	}
	zm.mu.RLock()
	if ids, ok := zm.portTMLCache[site][pair.Src+":"+pair.Dst]; ok {
		policy.SrcPortTMLID = ids.SrcTMLID
		policy.DstPortTMLID = ids.DstTMLID
		policy.DstIPTMLID = pickDstIPTML(ids.DstIPTMLIDs, ipv6)
	}
	zm.mu.RUnlock()
	return policy, nil
}

// ensurePolicy makes the controller hold desired: it adopts a policy with the
// same name, repairs one whose settings drifted, and otherwise creates it.
// existingByID is the site's current policy list and is kept up to date.
// delay pauses before a create. It reports whether a policy was created.
func (zm *ZoneManager) ensurePolicy(ctx context.Context, site string, desired controller.ZonePolicy,
	existingByID map[string]controller.ZonePolicy, delay bool,
) (bool, error) {
	name := desired.Name
	id, err := zm.resolvePolicyID(site, name, existingByID)
	if err != nil {
		return false, err
	}
	if id != "" {
		gone, err := zm.repairPolicy(ctx, site, existingByID[id], desired, existingByID)
		if err != nil || !gone {
			return false, err
		}
	}

	if delay && zm.cfg.APIWriteDelay > 0 {
		select {
		case <-time.After(zm.cfg.APIWriteDelay):
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
	created, err := zm.ctrl.CreateZonePolicy(ctx, site, desired)
	if err != nil {
		var conflict *controller.ErrConflict
		if !errors.As(err, &conflict) {
			return false, fmt.Errorf("create zone policy %s: %w", name, err)
		}
		recovered, found, lookupErr := zm.lookupPolicyByName(ctx, site, name)
		if lookupErr != nil || !found {
			return false, fmt.Errorf("create zone policy %s: %w", name, err)
		}
		zm.log.Warn().Str("policy", name).Str("id", recovered.ID).
			Msg("zone policy already exists (conflict); recovering it")
		if err := setCachedPolicy(zm.store, site, name, storage.PolicyRecord{UnifiID: recovered.ID, Site: site, Mode: "zone"}); err != nil {
			return false, fmt.Errorf("cache recovered zone policy %s: %w", name, err)
		}
		gone, err := zm.repairPolicy(ctx, site, recovered, desired, existingByID)
		if err == nil && gone {
			err = fmt.Errorf("zone policy %s disappeared during conflict recovery", name)
		}
		return false, err
	}
	existingByID[created.ID] = created
	if err := setCachedPolicy(zm.store, site, name, storage.PolicyRecord{UnifiID: created.ID, Site: site, Mode: "zone"}); err != nil {
		zm.log.Warn().Err(err).Str("policy", name).Msg("failed to cache policy in bbolt")
	}
	zm.log.Info().Str("name", name).Str("id", created.ID).
		Str("src", desired.SrcZone).Str("dst", desired.DstZone).Msg("created zone policy")
	return true, nil
}

// resolvePolicyID returns the ID of the listed policy named name, preferring
// the cached ID and adopting an uncached policy with the managed description.
// It returns "" when no such policy is listed.
func (zm *ZoneManager) resolvePolicyID(site, name string, existingByID map[string]controller.ZonePolicy) (string, error) {
	cached, err := getCachedPolicy(zm.store, site, name)
	if err != nil {
		return "", fmt.Errorf("lookup policy %s: %w", name, err)
	}
	if cached != nil {
		if p, ok := existingByID[cached.UnifiID]; ok && p.ID != "" {
			if p.Name != name {
				return "", fmt.Errorf("cached policy %s points to different API policy %s", name, p.Name)
			}
			return p.ID, nil
		}
	}
	for _, candidate := range existingByID {
		if candidate.Name != name {
			continue
		}
		if candidate.Description != zm.cfg.Description {
			return "", fmt.Errorf("policy %s exists with a different description", name)
		}
		if err := setCachedPolicy(zm.store, site, name, storage.PolicyRecord{UnifiID: candidate.ID, Site: site, Mode: "zone"}); err != nil {
			return "", fmt.Errorf("cache existing zone policy %s: %w", name, err)
		}
		return candidate.ID, nil
	}
	return "", nil
}

// repairPolicy brings current in line with desired. It reports gone when the
// controller confirms current no longer exists, so the caller recreates it.
func (zm *ZoneManager) repairPolicy(ctx context.Context, site string, current, desired controller.ZonePolicy,
	existingByID map[string]controller.ZonePolicy,
) (bool, error) {
	existingByID[current.ID] = current
	if !needsUpdateZonePolicy(current, desired) {
		zm.log.Debug().Str("policy", desired.Name).Msg("zone policy already exists")
		return false, nil
	}
	zm.log.Info().Str("policy", desired.Name).Msg("zone policy settings drifted; repairing")
	if current.SrcPortTMLID != desired.SrcPortTMLID || current.DstPortTMLID != desired.DstPortTMLID || current.DstIPTMLID != desired.DstIPTMLID {
		return false, zm.replacePolicy(ctx, site, current, desired, existingByID)
	}
	updated := desired
	updated.ID = current.ID
	updated.Index = current.Index
	err := zm.ctrl.UpdateZonePolicy(ctx, site, updated)
	if err == nil {
		existingByID[updated.ID] = updated
		return false, nil
	}
	var nf *controller.ErrNotFound
	if !errors.As(err, &nf) {
		return false, fmt.Errorf("update zone policy %s: %w", desired.Name, err)
	}
	return zm.confirmPolicyGone(ctx, site, current, existingByID)
}

// replacePolicy swaps current for desired when its filter lists change, which
// the controller's PUT endpoint cannot do. The replacement is staged under a
// temporary name first so a failed delete or rename never leaves the shard
// without a block policy.
func (zm *ZoneManager) replacePolicy(ctx context.Context, site string, current, desired controller.ZonePolicy,
	existingByID map[string]controller.ZonePolicy,
) error {
	name := desired.Name
	staged, err := zm.stageReplacementPolicy(ctx, site, desired, existingByID)
	if err != nil {
		return fmt.Errorf("stage replacement for zone policy %s: %w", name, err)
	}
	if err := zm.ctrl.DeleteZonePolicy(ctx, site, current.ID); err != nil {
		var nf *controller.ErrNotFound
		if !errors.As(err, &nf) {
			return fmt.Errorf("delete old zone policy %s after staging replacement: %w", name, err)
		}
	}
	delete(existingByID, current.ID)
	renamed := desired
	renamed.ID = staged.ID
	if err := zm.ctrl.UpdateZonePolicy(ctx, site, renamed); err != nil {
		return fmt.Errorf("rename staged zone policy %s: %w", name, err)
	}
	if err := setCachedPolicy(zm.store, site, name, storage.PolicyRecord{UnifiID: staged.ID, Site: site, Mode: "zone"}); err != nil {
		return fmt.Errorf("cache replacement zone policy %s: %w", name, err)
	}
	existingByID[staged.ID] = renamed
	return nil
}

// confirmPolicyGone handles a 404 on update. A restarting controller answers
// 404 for everything, so the policy counts as deleted only when a fresh listing
// no longer shows it. Otherwise it returns an error and the next pass retries,
// which never creates a duplicate.
func (zm *ZoneManager) confirmPolicyGone(ctx context.Context, site string, current controller.ZonePolicy,
	existingByID map[string]controller.ZonePolicy,
) (bool, error) {
	name := current.Name
	listed, found, err := zm.lookupPolicyByName(ctx, site, name)
	if err != nil {
		return false, fmt.Errorf("zone policy %s returned 404 and could not be re-listed (controller restarting?): %w", name, err)
	}
	if found {
		if listed.ID != current.ID {
			delete(existingByID, current.ID)
			existingByID[listed.ID] = listed
			if err := setCachedPolicy(zm.store, site, name, storage.PolicyRecord{UnifiID: listed.ID, Site: site, Mode: "zone"}); err != nil {
				return false, fmt.Errorf("cache relisted zone policy %s: %w", name, err)
			}
		}
		return false, fmt.Errorf("zone policy %s returned 404 but is still listed; retrying next sync", name)
	}
	zm.log.Warn().Str("policy", name).Str("id", current.ID).Msg("zone policy was deleted outside the bouncer; recreating it")
	delete(existingByID, current.ID)
	if err := deleteCachedPolicy(zm.store, site, name); err != nil {
		return false, fmt.Errorf("clear cached zone policy %s: %w", name, err)
	}
	return true, nil
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
		if needsUpdateZonePolicy(candidate, desired) {
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

// EnsurePoliciesForShard ensures the zone policies for a single new shard
// across all configured zone pairs. Called when a new shard overflows
// mid-operation.
func (zm *ZoneManager) EnsurePoliciesForShard(ctx context.Context, site, groupID string, ipv6 bool, shardIdx int) error {
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

	policies, err := zm.ctrl.ListZonePolicies(ctx, site)
	if err != nil {
		return fmt.Errorf("list policies for shard %d: %w", shardIdx, err)
	}
	existingByID := make(map[string]controller.ZonePolicy, len(policies))
	for _, p := range policies {
		existingByID[p.ID] = p
	}

	firstCreate := true
	for _, pair := range zm.cfg.ZonePairs {
		desired, err := zm.desiredPolicy(site, pair, zoneMap, ipv6, shardIdx, groupID)
		if err != nil {
			return err
		}
		created, err := zm.ensurePolicy(ctx, site, desired, existingByID, !firstCreate)
		if err != nil {
			return err
		}
		if created {
			firstCreate = false
		}
	}
	return nil
}

// cleanupOrphanedPortTMLs removes filter lists no longer referenced by the
// current pair configuration. IDs handle both base and content-versioned names.
// A list still referenced by any policy is kept: it may belong to another
// bouncer instance on the same site, or to a policy awaiting replacement.
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
	var candidates []controller.TrafficMatchingList
	for _, t := range allTMLs {
		if !expectedIDs[t.ID] && isFilterTMLName(t.Name) {
			candidates = append(candidates, t)
		}
	}
	if len(candidates) == 0 {
		return
	}
	policies, err := zm.ctrl.ListZonePolicies(ctx, site)
	if err != nil {
		zm.log.Warn().Err(err).Str("site", site).Msg("orphan port TML cleanup: failed to list policies")
		return
	}
	referenced := make(map[string]bool)
	for _, p := range policies {
		referenced[p.SrcPortTMLID] = true
		referenced[p.DstPortTMLID] = true
		referenced[p.DstIPTMLID] = true
	}
	for _, t := range candidates {
		if referenced[t.ID] {
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

// needsUpdateZonePolicy reports whether current differs from desired in any
// setting the bouncer manages: enabled state, action, zones, IP version,
// description, connection states, logging, the source list, and the port and
// destination-IP filter lists.
func needsUpdateZonePolicy(current, desired controller.ZonePolicy) bool {
	return current.Enabled != desired.Enabled ||
		current.Action != desired.Action ||
		current.SrcZone != desired.SrcZone ||
		current.DstZone != desired.DstZone ||
		current.IPVersion != desired.IPVersion ||
		current.Description != desired.Description ||
		current.LoggingEnabled != desired.LoggingEnabled ||
		!sameConnectionStates(current.ConnectionStateFilter, desired.ConnectionStateFilter) ||
		!slices.Equal(current.TrafficMatchingListIDs, desired.TrafficMatchingListIDs) ||
		current.SrcPortTMLID != desired.SrcPortTMLID ||
		current.DstPortTMLID != desired.DstPortTMLID ||
		current.DstIPTMLID != desired.DstIPTMLID
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

// lookupPolicyByName finds a zone policy by name. It is used for conflict
// recovery and to confirm a 404 before recreating a policy.
func (zm *ZoneManager) lookupPolicyByName(ctx context.Context, site, name string) (controller.ZonePolicy, bool, error) {
	policies, err := zm.ctrl.ListZonePolicies(ctx, site)
	if err != nil {
		return controller.ZonePolicy{}, false, fmt.Errorf("list zone policies: %w", err)
	}
	for _, p := range policies {
		if p.Name == name {
			return p, true, nil
		}
	}
	return controller.ZonePolicy{}, false, nil
}

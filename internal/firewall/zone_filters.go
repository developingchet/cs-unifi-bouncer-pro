package firewall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
)

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

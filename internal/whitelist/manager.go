package whitelist

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/rs/zerolog"
)

const (
	TMLNameV4            = "crowdsec-whitelist-cloudflare-v4"
	TMLNameV6            = "crowdsec-whitelist-cloudflare-v6"
	whitelistPrefix      = "crowdsec-whitelist-cloudflare-"
	whitelistDescription = "Managed by cs-unifi-bouncer-pro. Cloudflare whitelist. Do not edit manually."
)

// Manager maintains Cloudflare whitelist TMLs and ALLOW policies.
type Manager struct {
	ctrl     controller.Controller
	sites    []string
	provider *CloudflareProvider
	log      zerolog.Logger
}

// NewManager creates a whitelist Manager.
func NewManager(ctrl controller.Controller, sites []string, provider *CloudflareProvider, log zerolog.Logger) *Manager {
	return &Manager{ctrl: ctrl, sites: sites, provider: provider, log: log}
}

// ZonePairConfig holds zone IDs for a source/destination pair, with optional port and IP filters.
type ZonePairConfig struct {
	SrcName   string
	DstName   string
	SrcZoneID string
	DstZoneID string
	SrcPorts  []int    // empty = any source ports
	DstPorts  []int    // empty = any destination ports
	DstIPs    []string // empty = any destination IPs; CIDRs or plain IPs, IPv4 or IPv6
}

// Sync fetches current Cloudflare IPs and ensures TMLs are up to date.
// Call at startup and on each weekly tick.
func (m *Manager) Sync(ctx context.Context, zonePairs []ZonePairConfig) error {
	ipv4, err := m.provider.FetchIPv4(ctx)
	if err != nil {
		return fmt.Errorf("fetch Cloudflare IPv4: %w", err)
	}
	ipv6, err := m.provider.FetchIPv6(ctx)
	if err != nil {
		return fmt.Errorf("fetch Cloudflare IPv6: %w", err)
	}

	var siteErrors []error
	for _, site := range m.sites {
		if err := m.syncSite(ctx, site, ipv4, ipv6, zonePairs); err != nil {
			m.log.Error().Err(err).Str("site", site).Msg("Cloudflare whitelist sync failed for site")
			siteErrors = append(siteErrors, fmt.Errorf("site %s: %w", site, err))
		}
	}
	return errors.Join(siteErrors...)
}

func (m *Manager) syncSite(ctx context.Context, site string, ipv4, ipv6 []string, zonePairs []ZonePairConfig) error {
	// Build items slices for IP TMLs.
	v4Items := make([]controller.TrafficMatchingListItem, 0, len(ipv4))
	for _, cidr := range ipv4 {
		v4Items = append(v4Items, controller.TrafficMatchingListItem{Type: "SUBNET", Value: cidr})
	}
	v6Items := make([]controller.TrafficMatchingListItem, 0, len(ipv6))
	for _, cidr := range ipv6 {
		v6Items = append(v6Items, controller.TrafficMatchingListItem{Type: "SUBNET", Value: cidr})
	}

	// Ensure/update IP TMLs.
	tmlV4, err := m.ensureTML(ctx, site, TMLNameV4, "IPV4_ADDRESSES", v4Items)
	if err != nil {
		return fmt.Errorf("ensure v4 TML: %w", err)
	}
	tmlV6, err := m.ensureTML(ctx, site, TMLNameV6, "IPV6_ADDRESSES", v6Items)
	if err != nil {
		return fmt.Errorf("ensure v6 TML: %w", err)
	}

	existingPolicies, err := m.ctrl.ListZonePolicies(ctx, site)
	if err != nil {
		return fmt.Errorf("list zone policies for site %s: %w", site, err)
	}

	// Ensure ALLOW policies for each zone pair, creating port TMLs as needed.
	// Track managed policy IDs (exact IDs returned by ensureAllowPolicy) and
	// managed base names (forward policy names, for Return mirror matching).
	// Using ID-based tracking ensures duplicate-named stale policies are cleaned up.
	managedPolicyIDs := make(map[string]bool)
	managedBaseNames := make(map[string]bool)
	expectedTMLNames := map[string]bool{TMLNameV4: true, TMLNameV6: true}

	for _, pair := range zonePairs {
		if pair.SrcZoneID == "" {
			id, err := m.ctrl.GetZoneID(ctx, site, pair.SrcName)
			if err != nil {
				return fmt.Errorf("resolve source zone %q: %w", pair.SrcName, err)
			}
			pair.SrcZoneID = id
		}
		if pair.DstZoneID == "" {
			id, err := m.ctrl.GetZoneID(ctx, site, pair.DstName)
			if err != nil {
				return fmt.Errorf("resolve destination zone %q: %w", pair.DstName, err)
			}
			pair.DstZoneID = id
		}
		var srcPortTMLID, dstPortTMLID string
		srcPortTMLName := "crowdsec-whitelist-cloudflare-srcports-" + pair.SrcName + "-" + pair.DstName
		dstPortTMLName := "crowdsec-whitelist-cloudflare-dstports-" + pair.SrcName + "-" + pair.DstName

		if len(pair.SrcPorts) > 0 {
			portItems := portsToItems(pair.SrcPorts)
			t, portErr := m.ensureTML(ctx, site, srcPortTMLName, "PORTS", portItems)
			if portErr != nil {
				return fmt.Errorf("ensure source port TML for %s->%s: %w", pair.SrcName, pair.DstName, portErr)
			}
			srcPortTMLID = t.ID
			expectedTMLNames[srcPortTMLName] = true
		}
		if len(pair.DstPorts) > 0 {
			portItems := portsToItems(pair.DstPorts)
			t, portErr := m.ensureTML(ctx, site, dstPortTMLName, "PORTS", portItems)
			if portErr != nil {
				return fmt.Errorf("ensure destination port TML for %s->%s: %w", pair.SrcName, pair.DstName, portErr)
			}
			dstPortTMLID = t.ID
			expectedTMLNames[dstPortTMLName] = true
		}

		// Create/ensure destination IP TMLs (one per IP family) when DstIPs are configured.
		// dstIPTMLIDs is ordered: v4 TML first (if present), v6 TML second.
		var dstIPTMLIDs []string
		if len(pair.DstIPs) > 0 {
			v4IPs, v6IPs := splitByFamily(pair.DstIPs)
			if len(v4IPs) > 0 {
				dstIPv4TMLName := "crowdsec-whitelist-cloudflare-dstips-" + pair.SrcName + "-" + pair.DstName + "-v4"
				t, ipErr := m.ensureTML(ctx, site, dstIPv4TMLName, "IPV4_ADDRESSES", ipsToItems(v4IPs))
				if ipErr != nil {
					return fmt.Errorf("ensure destination IPv4 TML for %s->%s: %w", pair.SrcName, pair.DstName, ipErr)
				}
				dstIPTMLIDs = append(dstIPTMLIDs, t.ID)
				expectedTMLNames[dstIPv4TMLName] = true
			}
			if len(v6IPs) > 0 {
				dstIPv6TMLName := "crowdsec-whitelist-cloudflare-dstips-" + pair.SrcName + "-" + pair.DstName + "-v6"
				t, ipErr := m.ensureTML(ctx, site, dstIPv6TMLName, "IPV6_ADDRESSES", ipsToItems(v6IPs))
				if ipErr != nil {
					return fmt.Errorf("ensure destination IPv6 TML for %s->%s: %w", pair.SrcName, pair.DstName, ipErr)
				}
				dstIPTMLIDs = append(dstIPTMLIDs, t.ID)
				expectedTMLNames[dstIPv6TMLName] = true
			}
		}
		dstIPTMLIDForV4 := pickDstIPTML(dstIPTMLIDs, false)
		dstIPTMLIDForV6 := pickDstIPTML(dstIPTMLIDs, true)

		v4Name := "crowdsec-whitelist-cloudflare-" + pair.SrcName + "-" + pair.DstName + "-v4"
		v6Name := "crowdsec-whitelist-cloudflare-" + pair.SrcName + "-" + pair.DstName + "-v6"
		// Register base names so their UniFi-managed (Return) mirrors are preserved.
		managedBaseNames[v4Name] = true
		managedBaseNames[v6Name] = true

		var pairPolicyIDs []string
		p, err := m.ensureAllowPolicy(ctx, site, pair, tmlV4.ID, srcPortTMLID, dstPortTMLID, dstIPTMLIDForV4, "IPV4", v4Name, existingPolicies)
		if err != nil {
			return fmt.Errorf("ensure IPv4 allow policy for %s->%s: %w", pair.SrcName, pair.DstName, err)
		}
		managedPolicyIDs[p.ID] = true
		pairPolicyIDs = append(pairPolicyIDs, p.ID)
		p, err = m.ensureAllowPolicy(ctx, site, pair, tmlV6.ID, srcPortTMLID, dstPortTMLID, dstIPTMLIDForV6, "IPV6", v6Name, existingPolicies)
		if err != nil {
			return fmt.Errorf("ensure IPv6 allow policy for %s->%s: %w", pair.SrcName, pair.DstName, err)
		}
		managedPolicyIDs[p.ID] = true
		pairPolicyIDs = append(pairPolicyIDs, p.ID)

		// Verify that the controller evaluates the allow policies before blocks.
		if len(pairPolicyIDs) > 0 {
			if err := m.checkWhitelistOrder(ctx, site, pair, pairPolicyIDs); err != nil {
				return err
			}
		}
	}

	// Sweep for orphaned whitelist policies — managed by this bouncer but no
	// longer declared in CLOUDFLARE_ZONE_PAIRS.
	for _, p := range existingPolicies {
		if !strings.HasPrefix(p.Name, whitelistPrefix) {
			continue
		}
		// UniFi auto-creates a "(Return)" mirror for every ALLOW policy with
		// AllowReturnTraffic=true. Handle Return mirrors and forward policies separately.
		baseName := strings.TrimSuffix(p.Name, " (Return)")
		if baseName != p.Name {
			// Return mirror: keep if its base forward policy is currently managed.
			if managedBaseNames[baseName] {
				continue
			}
		} else {
			// Forward policy: keep only if this exact ID is actively managed.
			// ID-based tracking correctly handles duplicate-named policies — only
			// the specific policy returned by ensureAllowPolicy is protected.
			if managedPolicyIDs[p.ID] {
				continue
			}
			// Not actively managed by ID — only delete if it's ours to clean up
			// (our description, or empty description from before description support).
			if p.Description != whitelistDescription && p.Description != "" {
				continue
			}
		}
		if err := m.ctrl.DeleteZonePolicy(ctx, site, p.ID); err != nil {
			m.log.Warn().Err(err).Str("policy", p.Name).Msg("failed to delete orphaned whitelist policy")
		} else {
			m.log.Info().Str("policy", p.Name).Str("site", site).
				Msg("deleted orphaned Cloudflare whitelist policy (zone pair removed from config)")
		}
	}

	// Sweep for orphaned port-filter TMLs (srcports/dstports) that no longer
	// correspond to any configured CLOUDFLARE_ZONE_PAIRS entry with port filters.
	allTMLs, tmlErr := m.ctrl.ListTrafficMatchingLists(ctx, site)
	if tmlErr != nil {
		m.log.Warn().Err(tmlErr).Str("site", site).Msg("failed to list TMLs for orphan sweep")
	} else {
		for _, t := range allTMLs {
			if !strings.HasPrefix(t.Name, whitelistPrefix) {
				continue
			}
			// Only target per-pair filter TMLs (srcports / dstports / dstips), not the IP TMLs.
			if !strings.Contains(t.Name, "srcports-") && !strings.Contains(t.Name, "dstports-") && !strings.Contains(t.Name, "dstips-") {
				continue
			}
			if expectedTMLNames[t.Name] {
				continue
			}
			if err := m.ctrl.DeleteTrafficMatchingList(ctx, site, t.ID); err != nil {
				m.log.Warn().Err(err).Str("tml", t.Name).Msg("failed to delete orphaned whitelist port TML")
			} else {
				m.log.Info().Str("tml", t.Name).Str("site", site).
					Msg("deleted orphaned Cloudflare whitelist port TML (zone pair removed from config)")
			}
		}
	}

	return nil
}

// pickDstIPTML selects the destination IP TML ID for a policy.
//
// ids is an ordered slice of dst IP TML IDs: v4 TML first (if present), v6 second.
// Selection rule:
//
//	len 0 → ""             no destination IP filter configured
//	len 1 → ids[0]         single-family: both v4 and v6 policies share the same TML
//	len 2 → ids[1] if ipv6 mixed: each policy uses the TML whose family matches (API ceiling)
//	         ids[0] otherwise
func pickDstIPTML(ids []string, ipv6 bool) string {
	switch len(ids) {
	case 0:
		return ""
	case 1:
		return ids[0]
	default:
		if ipv6 {
			return ids[1]
		}
		return ids[0]
	}
}

// splitByFamily splits a slice of IPs/CIDRs into IPv4 and IPv6 buckets.
func splitByFamily(ips []string) (v4, v6 []string) {
	for _, ip := range ips {
		addr := ip
		if idx := strings.Index(ip, "/"); idx != -1 {
			addr = ip[:idx]
		}
		parsed := net.ParseIP(addr)
		if parsed == nil {
			continue
		}
		if parsed.To4() != nil {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}
	return
}

// ipsToItems converts a slice of IP/CIDR strings to TrafficMatchingListItems.
func ipsToItems(ips []string) []controller.TrafficMatchingListItem {
	items := make([]controller.TrafficMatchingListItem, 0, len(ips))
	for _, ip := range ips {
		t := "IP_ADDRESS"
		if strings.Contains(ip, "/") {
			t = "SUBNET"
		}
		items = append(items, controller.TrafficMatchingListItem{Type: t, Value: ip})
	}
	return items
}

// portsToItems converts a slice of port integers to TrafficMatchingListItems.
func portsToItems(ports []int) []controller.TrafficMatchingListItem {
	items := make([]controller.TrafficMatchingListItem, 0, len(ports))
	for _, p := range ports {
		items = append(items, controller.TrafficMatchingListItem{Type: "PORT_NUMBER", Value: strconv.Itoa(p)})
	}
	return items
}

func (m *Manager) ensureTML(ctx context.Context, site, name, tmlType string, items []controller.TrafficMatchingListItem) (controller.TrafficMatchingList, error) {
	existing, err := m.ctrl.ListTrafficMatchingLists(ctx, site)
	if err != nil {
		return controller.TrafficMatchingList{}, err
	}

	var found *controller.TrafficMatchingList
	for i := range existing {
		if existing[i].Name == name {
			found = &existing[i]
			break
		}
	}

	if found == nil {
		created, err := m.ctrl.CreateTrafficMatchingList(ctx, site, controller.TrafficMatchingList{
			Name:  name,
			Type:  tmlType,
			Items: items,
		})
		if err != nil {
			return controller.TrafficMatchingList{}, fmt.Errorf("create TML %s: %w", name, err)
		}
		m.log.Info().Str("tml", name).Str("id", created.ID).Int("items", len(items)).Msg("created whitelist TML")
		return created, nil
	}

	// Compare current vs desired.
	if !tmlItemsEqual(found.Items, items) {
		found.Items = items
		if err := m.ctrl.UpdateTrafficMatchingList(ctx, site, *found); err != nil {
			return controller.TrafficMatchingList{}, fmt.Errorf("update TML %s: %w", name, err)
		}
		m.log.Info().Str("tml", name).Int("items", len(items)).Msg("updated whitelist TML")
	} else {
		m.log.Debug().Str("tml", name).Msg("whitelist TML unchanged")
	}
	return *found, nil
}

func (m *Manager) ensureAllowPolicy(ctx context.Context, site string, pair ZonePairConfig, ipTMLID, srcPortTMLID, dstPortTMLID, dstIPTMLID, ipVersion, policyName string, existingPolicies []controller.ZonePolicy) (controller.ZonePolicy, error) {
	// Guard against empty TML ID - Cloudflare ALLOW policies MUST have a source filter
	if ipTMLID == "" {
		return controller.ZonePolicy{}, fmt.Errorf("cloudflare TML ID is empty for policy %s in site %s: cannot create ALLOW policy without source filter", policyName, site)
	}

	desired := controller.ZonePolicy{
		Name:                   policyName,
		Enabled:                true,
		Action:                 "ALLOW",
		AllowReturnTraffic:     true,
		SrcZone:                pair.SrcZoneID,
		DstZone:                pair.DstZoneID,
		IPVersion:              ipVersion,
		Description:            whitelistDescription,
		TrafficMatchingListIDs: []string{ipTMLID},
		SrcPortTMLID:           srcPortTMLID,
		DstPortTMLID:           dstPortTMLID,
		DstIPTMLID:             dstIPTMLID,
	}
	for _, p := range existingPolicies {
		if p.Name == policyName {
			if p.Description != "" && p.Description != whitelistDescription {
				return controller.ZonePolicy{}, fmt.Errorf("policy %s in site %s has a different owner description", policyName, site)
			}
			if p.Enabled && p.Action == desired.Action && p.AllowReturnTraffic &&
				p.SrcZone == desired.SrcZone && p.DstZone == desired.DstZone && p.IPVersion == desired.IPVersion &&
				p.Description == desired.Description && !p.LoggingEnabled && len(p.ConnectionStateFilter) == 0 &&
				len(p.TrafficMatchingListIDs) == 1 && p.TrafficMatchingListIDs[0] == ipTMLID &&
				p.SrcPortTMLID == srcPortTMLID && p.DstPortTMLID == dstPortTMLID && p.DstIPTMLID == dstIPTMLID {
				return p, nil // up to date
			}

			// If portFilter or dstIPTMLID is changing, the UniFi PUT endpoint rejects
			// these fields. Recreate to also clear any existing connection state filter.
			filterChanging := p.SrcPortTMLID != srcPortTMLID || p.DstPortTMLID != dstPortTMLID || p.DstIPTMLID != dstIPTMLID || len(p.ConnectionStateFilter) > 0
			if filterChanging {
				m.log.Info().Str("policy", policyName).Str("site", site).
					Msg("filter changed on existing policy — deleting for recreation with new filter")
				if delErr := m.ctrl.DeleteZonePolicy(ctx, site, p.ID); delErr != nil {
					return controller.ZonePolicy{}, fmt.Errorf("delete policy %s before filter recreation: %w", policyName, delErr)
				}
				// Fall through to the creation path below.
				break
			}

			// PUT preserves the port and destination IP filters.
			desired.ID = p.ID
			if err := m.ctrl.UpdateZonePolicy(ctx, site, desired); err != nil {
				return controller.ZonePolicy{}, fmt.Errorf("update allow policy %s: %w", policyName, err)
			}
			return desired, nil
		}
	}

	created, err := m.ctrl.CreateZonePolicy(ctx, site, desired)
	if err != nil {
		return controller.ZonePolicy{}, fmt.Errorf("create allow policy %s: %w", policyName, err)
	}
	m.log.Info().Str("policy", policyName).Str("site", site).Msg("created Cloudflare whitelist ALLOW policy")
	return created, nil
}

// checkWhitelistOrder detects a block that would take precedence over a
// Cloudflare allow. Integration-created policies cannot be moved with the
// user-defined policy ordering endpoint.
func (m *Manager) checkWhitelistOrder(ctx context.Context, site string, pair ZonePairConfig, policyIDs []string) error {
	policies, err := m.ctrl.ListZonePolicies(ctx, site)
	if err != nil {
		return fmt.Errorf("list policies to verify Cloudflare order in site %s: %w", site, err)
	}
	allows := make(map[string]controller.ZonePolicy, len(policyIDs))
	for _, p := range policies {
		for _, id := range policyIDs {
			if p.ID == id {
				allows[id] = p
			}
		}
	}
	for _, id := range policyIDs {
		allow, found := allows[id]
		if !found {
			return fmt.Errorf("cloudflare allow policy %s missing from site %s after sync", id, site)
		}
		for _, p := range policies {
			if !p.Enabled || p.Action != "BLOCK" || p.SrcZone != pair.SrcZoneID || p.DstZone != pair.DstZoneID {
				continue
			}
			if p.IPVersion != "" && p.IPVersion != "BOTH" && p.IPVersion != allow.IPVersion {
				continue
			}
			if allow.Index == nil || p.Index == nil {
				return fmt.Errorf("cannot verify Cloudflare allow policy %s precedes block %s in site %s: policy index missing", allow.Name, p.Name, site)
			}
			if *p.Index <= *allow.Index {
				return fmt.Errorf("cloudflare allow policy %s follows block %s in site %s; recreate the block after the allow policy", allow.Name, p.Name, site)
			}
		}
	}
	return nil
}

// Drain removes all Cloudflare whitelist policies and TMLs from all managed
// sites. Call when CLOUDFLARE_WHITELIST_ENABLED is set to false so that
// previously-created objects are cleaned up rather than left as orphans.
// The provider is not used — no live Cloudflare IPs are fetched.
func (m *Manager) Drain(ctx context.Context) error {
	for _, site := range m.sites {
		policies, err := m.ctrl.ListZonePolicies(ctx, site)
		if err != nil {
			m.log.Warn().Err(err).Str("site", site).Msg("Cloudflare drain: failed to list zone policies")
		} else {
			for _, p := range policies {
				if !strings.HasPrefix(p.Name, whitelistPrefix) {
					continue
				}
				// Return mirrors are auto-created by UniFi — no description to check.
				// Forward policies: only delete if description marks them as ours.
				baseName := strings.TrimSuffix(p.Name, " (Return)")
				if baseName == p.Name && p.Description != whitelistDescription && p.Description != "" {
					continue
				}
				if err := m.ctrl.DeleteZonePolicy(ctx, site, p.ID); err != nil {
					m.log.Warn().Err(err).Str("policy", p.Name).Str("site", site).
						Msg("Cloudflare drain: failed to delete whitelist policy")
				} else {
					m.log.Info().Str("policy", p.Name).Str("site", site).
						Msg("Cloudflare drain: deleted whitelist policy")
				}
			}
		}

		tmls, err := m.ctrl.ListTrafficMatchingLists(ctx, site)
		if err != nil {
			m.log.Warn().Err(err).Str("site", site).Msg("Cloudflare drain: failed to list TMLs")
		} else {
			for _, t := range tmls {
				if !strings.HasPrefix(t.Name, whitelistPrefix) {
					continue
				}
				if err := m.ctrl.DeleteTrafficMatchingList(ctx, site, t.ID); err != nil {
					m.log.Warn().Err(err).Str("tml", t.Name).Str("site", site).
						Msg("Cloudflare drain: failed to delete whitelist TML")
				} else {
					m.log.Info().Str("tml", t.Name).Str("site", site).
						Msg("Cloudflare drain: deleted whitelist TML")
				}
			}
		}
	}
	return nil
}

// tmlItemsEqual returns true if two TML item slices have the same values (order-independent).
func tmlItemsEqual(existing, desired []controller.TrafficMatchingListItem) bool {
	if len(existing) != len(desired) {
		return false
	}
	curr := make([]string, len(existing))
	for i, item := range existing {
		curr[i] = item.Value
	}
	want := make([]string, len(desired))
	for i, item := range desired {
		want[i] = item.Value
	}
	sort.Strings(curr)
	sort.Strings(want)
	for i := range curr {
		if curr[i] != want[i] {
			return false
		}
	}
	return true
}

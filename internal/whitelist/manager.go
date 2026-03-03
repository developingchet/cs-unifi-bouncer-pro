package whitelist

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/rs/zerolog"
)

const (
	TMLNameV4 = "crowdsec-whitelist-cloudflare-v4"
	TMLNameV6 = "crowdsec-whitelist-cloudflare-v6"
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

// ZonePairConfig holds zone IDs for a source/destination pair, with optional port filters.
type ZonePairConfig struct {
	SrcName   string
	DstName   string
	SrcZoneID string
	DstZoneID string
	SrcPorts  []int // empty = any source ports
	DstPorts  []int // empty = any destination ports
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

	for _, site := range m.sites {
		if err := m.syncSite(ctx, site, ipv4, ipv6, zonePairs); err != nil {
			m.log.Error().Err(err).Str("site", site).Msg("Cloudflare whitelist sync failed for site")
		}
	}
	return nil
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
	// Track expected policy and TML names for the orphan sweep below.
	expectedPolicyNames := make(map[string]bool)
	expectedTMLNames := map[string]bool{TMLNameV4: true, TMLNameV6: true}

	for _, pair := range zonePairs {
		var srcPortTMLID, dstPortTMLID string
		srcPortTMLName := "crowdsec-whitelist-cloudflare-srcports-" + pair.SrcName + "-" + pair.DstName
		dstPortTMLName := "crowdsec-whitelist-cloudflare-dstports-" + pair.SrcName + "-" + pair.DstName

		if len(pair.SrcPorts) > 0 {
			portItems := portsToItems(pair.SrcPorts)
			t, portErr := m.ensureTML(ctx, site, srcPortTMLName, "PORTS", portItems)
			if portErr != nil {
				m.log.Error().Err(portErr).Str("pair", pair.SrcName+"->"+pair.DstName).Msg("ensure src port TML failed")
			} else {
				srcPortTMLID = t.ID
				expectedTMLNames[srcPortTMLName] = true
			}
		}
		if len(pair.DstPorts) > 0 {
			portItems := portsToItems(pair.DstPorts)
			t, portErr := m.ensureTML(ctx, site, dstPortTMLName, "PORTS", portItems)
			if portErr != nil {
				m.log.Error().Err(portErr).Str("pair", pair.SrcName+"->"+pair.DstName).Msg("ensure dst port TML failed")
			} else {
				dstPortTMLID = t.ID
				expectedTMLNames[dstPortTMLName] = true
			}
		}

		v4Name := "crowdsec-whitelist-cloudflare-External-" + pair.DstName + "-v4"
		v6Name := "crowdsec-whitelist-cloudflare-External-" + pair.DstName + "-v6"
		expectedPolicyNames[v4Name] = true
		expectedPolicyNames[v6Name] = true

		if err := m.ensureAllowPolicy(ctx, site, pair, tmlV4.ID, srcPortTMLID, dstPortTMLID, "IPV4", v4Name, existingPolicies); err != nil {
			m.log.Error().Err(err).Str("pair", pair.SrcName+"->"+pair.DstName).Msg("ensure v4 allow policy failed")
		}
		if err := m.ensureAllowPolicy(ctx, site, pair, tmlV6.ID, srcPortTMLID, dstPortTMLID, "IPV6", v6Name, existingPolicies); err != nil {
			m.log.Error().Err(err).Str("pair", pair.SrcName+"->"+pair.DstName).Msg("ensure v6 allow policy failed")
		}
	}

	// Sweep for orphaned whitelist policies — managed by this bouncer but no
	// longer declared in CLOUDFLARE_ZONE_PAIRS.
	const (
		whitelistPolicyPrefix = "crowdsec-whitelist-cloudflare-"
		whitelistDesc         = "Managed by cs-unifi-bouncer-pro. Cloudflare whitelist. Do not edit manually."
	)
	for _, p := range existingPolicies {
		if !strings.HasPrefix(p.Name, whitelistPolicyPrefix) {
			continue
		}
		if p.Description != whitelistDesc {
			continue
		}
		if expectedPolicyNames[p.Name] {
			continue
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
	const portTMLPrefix = "crowdsec-whitelist-cloudflare-"
	allTMLs, tmlErr := m.ctrl.ListTrafficMatchingLists(ctx, site)
	if tmlErr != nil {
		m.log.Warn().Err(tmlErr).Str("site", site).Msg("failed to list TMLs for orphan sweep")
	} else {
		for _, t := range allTMLs {
			if !strings.HasPrefix(t.Name, portTMLPrefix) {
				continue
			}
			// Only target port-filter TMLs (srcports / dstports), not the IP TMLs.
			if !strings.Contains(t.Name, "srcports-") && !strings.Contains(t.Name, "dstports-") {
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

func (m *Manager) ensureAllowPolicy(ctx context.Context, site string, pair ZonePairConfig, ipTMLID, srcPortTMLID, dstPortTMLID, ipVersion, policyName string, existingPolicies []controller.ZonePolicy) error {
	// Guard against empty TML ID - Cloudflare ALLOW policies MUST have a source filter
	if ipTMLID == "" {
		return fmt.Errorf("Cloudflare TML ID is empty for policy %s in site %s — cannot create ALLOW policy without source filter", policyName, site)
	}

	for _, p := range existingPolicies {
		if p.Name == policyName {
			// Already exists; check if IP TML ID and port TML IDs all match.
			if len(p.TrafficMatchingListIDs) > 0 && p.TrafficMatchingListIDs[0] == ipTMLID &&
				p.SrcPortTMLID == srcPortTMLID && p.DstPortTMLID == dstPortTMLID {
				return nil // up to date
			}

			// If portFilter is changing, the UniFi PUT endpoint rejects portFilter
			// in the request body. Delete and recreate so portFilter takes effect via POST.
			portFilterChanging := p.SrcPortTMLID != srcPortTMLID || p.DstPortTMLID != dstPortTMLID
			if portFilterChanging {
				m.log.Info().Str("policy", policyName).Str("site", site).
					Msg("portFilter changed on existing policy — deleting for recreation with new portFilter")
				if delErr := m.ctrl.DeleteZonePolicy(ctx, site, p.ID); delErr != nil {
					return fmt.Errorf("delete policy %s before portFilter recreation: %w", policyName, delErr)
				}
				// Fall through to the creation path below.
				break
			}

			// portFilter is unchanged; only the IP TML changed. Use PUT (portFilter
			// is not in the PUT body, server preserves the existing value).
			p.TrafficMatchingListIDs = []string{ipTMLID}
			p.ConnectionStateFilter = nil
			p.AllowReturnTraffic = true
			return m.ctrl.UpdateZonePolicy(ctx, site, p)
		}
	}

	_, err := m.ctrl.CreateZonePolicy(ctx, site, controller.ZonePolicy{
		Name:               policyName,
		Enabled:            true,
		Action:             "ALLOW",
		AllowReturnTraffic: true,
		SrcZone:            pair.SrcZoneID,
		DstZone:            pair.DstZoneID,
		IPVersion:          ipVersion,
		Description:        "Managed by cs-unifi-bouncer-pro. Cloudflare whitelist. Do not edit manually.",
		TrafficMatchingListIDs: []string{ipTMLID},
		ConnectionStateFilter:  nil, // All
		SrcPortTMLID:           srcPortTMLID,
		DstPortTMLID:           dstPortTMLID,
	})
	if err != nil {
		return fmt.Errorf("create allow policy %s: %w", policyName, err)
	}
	m.log.Info().Str("policy", policyName).Str("site", site).Msg("created Cloudflare whitelist ALLOW policy")
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

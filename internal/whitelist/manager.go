package whitelist

import (
	"context"
	"fmt"
	"sort"

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

// ZonePairConfig holds zone IDs for a source/destination pair.
type ZonePairConfig struct {
	SrcName   string
	DstName   string
	SrcZoneID string
	DstZoneID string
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
	// Ensure/update TMLs.
	tmlV4, err := m.ensureTML(ctx, site, TMLNameV4, "IPV4_ADDRESSES", ipv4)
	if err != nil {
		return fmt.Errorf("ensure v4 TML: %w", err)
	}
	tmlV6, err := m.ensureTML(ctx, site, TMLNameV6, "IPV6_ADDRESSES", ipv6)
	if err != nil {
		return fmt.Errorf("ensure v6 TML: %w", err)
	}

	// Ensure ALLOW policies for each zone pair.
	for _, pair := range zonePairs {
		if err := m.ensureAllowPolicy(ctx, site, pair, tmlV4.ID, "IPV4", "crowdsec-whitelist-cloudflare-External-"+pair.DstName+"-v4"); err != nil {
			m.log.Error().Err(err).Str("pair", pair.SrcName+"->"+pair.DstName).Msg("ensure v4 allow policy failed")
		}
		if err := m.ensureAllowPolicy(ctx, site, pair, tmlV6.ID, "IPV6", "crowdsec-whitelist-cloudflare-External-"+pair.DstName+"-v6"); err != nil {
			m.log.Error().Err(err).Str("pair", pair.SrcName+"->"+pair.DstName).Msg("ensure v6 allow policy failed")
		}
	}
	return nil
}

func (m *Manager) ensureTML(ctx context.Context, site, name, tmlType string, cidrs []string) (controller.TrafficMatchingList, error) {
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

	items := make([]controller.TrafficMatchingListItem, 0, len(cidrs))
	for _, cidr := range cidrs {
		items = append(items, controller.TrafficMatchingListItem{Value: cidr})
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
		m.log.Info().Str("tml", name).Str("id", created.ID).Int("cidrs", len(cidrs)).Msg("created Cloudflare whitelist TML")
		return created, nil
	}

	// Compare current vs desired.
	if !tmlItemsEqual(found.Items, cidrs) {
		found.Items = items
		if err := m.ctrl.UpdateTrafficMatchingList(ctx, site, *found); err != nil {
			return controller.TrafficMatchingList{}, fmt.Errorf("update TML %s: %w", name, err)
		}
		m.log.Info().Str("tml", name).Int("cidrs", len(cidrs)).Msg("updated Cloudflare whitelist TML")
	} else {
		m.log.Debug().Str("tml", name).Msg("Cloudflare whitelist TML unchanged")
	}
	return *found, nil
}

func (m *Manager) ensureAllowPolicy(ctx context.Context, site string, pair ZonePairConfig, tmlID, ipVersion, policyName string) error {
	// Guard against empty TML ID - Cloudflare ALLOW policies MUST have a source filter
	if tmlID == "" {
		return fmt.Errorf("Cloudflare TML ID is empty for policy %s in site %s — cannot create ALLOW policy without source filter", policyName, site)
	}

	policies, err := m.ctrl.ListZonePolicies(ctx, site)
	if err != nil {
		return err
	}

	for _, p := range policies {
		if p.Name == policyName {
			// Already exists; check if TML ID matches.
			if len(p.TrafficMatchingListIDs) > 0 && p.TrafficMatchingListIDs[0] == tmlID {
				return nil // up to date
			}
			p.TrafficMatchingListIDs = []string{tmlID}
			p.ConnectionStateFilter = nil
			return m.ctrl.UpdateZonePolicy(ctx, site, p)
		}
	}

	_, err = m.ctrl.CreateZonePolicy(ctx, site, controller.ZonePolicy{
		Name:        policyName,
		Enabled:     true,
		Action:      "ALLOW",
		SrcZone:     pair.SrcZoneID,
		DstZone:     pair.DstZoneID,
		IPVersion:   ipVersion,
		Description: "Managed by cs-unifi-bouncer-pro. Cloudflare whitelist. Do not edit manually.",
		TrafficMatchingListIDs: []string{tmlID},
		ConnectionStateFilter:  nil, // All
	})
	if err != nil {
		return fmt.Errorf("create allow policy %s: %w", policyName, err)
	}
	m.log.Info().Str("policy", policyName).Str("site", site).Msg("created Cloudflare whitelist ALLOW policy")
	return nil
}

// tmlItemsEqual returns true if the TML items match the desired CIDR list (order-independent).
func tmlItemsEqual(items []controller.TrafficMatchingListItem, cidrs []string) bool {
	if len(items) != len(cidrs) {
		return false
	}
	current := make([]string, len(items))
	for i, item := range items {
		current[i] = item.Value
	}
	desired := make([]string, len(cidrs))
	copy(desired, cidrs)
	sort.Strings(current)
	sort.Strings(desired)
	for i := range current {
		if current[i] != desired[i] {
			return false
		}
	}
	return true
}

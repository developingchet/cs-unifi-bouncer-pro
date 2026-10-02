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
	blocks   BlockRecreator
	log      zerolog.Logger
}

// BlockRecreator recreates block policies by ID, so the controller evaluates
// them after policies created before the call.
type BlockRecreator interface {
	RecreatePolicies(ctx context.Context, site string, ids []string) error
}

// NewManager creates a whitelist Manager.
func NewManager(ctrl controller.Controller, sites []string, provider *CloudflareProvider, log zerolog.Logger) *Manager {
	return &Manager{ctrl: ctrl, sites: sites, provider: provider, log: log}
}

// SetBlockRecreator lets the manager recreate block policies that the
// controller evaluates before a Cloudflare allow. Without one, such an order
// is only reported.
func (m *Manager) SetBlockRecreator(r BlockRecreator) {
	m.blocks = r
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

// whitelistName names a per-pair whitelist object:
// whitelistPrefix + kind + "<src>-<dst>" + suffix.
func whitelistName(kind string, pair ZonePairConfig, suffix string) string {
	return whitelistPrefix + kind + pair.SrcName + "-" + pair.DstName + suffix
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
	// Track managed policy IDs (exact IDs returned by ensureAllowPolicy).
	// Using ID-based tracking ensures duplicate-named stale policies are cleaned up.
	managedPolicyIDs := make(map[string]bool)
	expectedTMLNames := map[string]bool{TMLNameV4: true, TMLNameV6: true}
	var orderErrs []error

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
		srcPortTMLName := whitelistName("srcports-", pair, "")
		dstPortTMLName := whitelistName("dstports-", pair, "")

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

		// With destination IPs of one family only, the other family gets no ALLOW
		// policy: UniFi rejects a policy whose destination list is of the other
		// family (HTTP 500), and that family cannot reach those destinations anyway.
		// An existing policy for it is removed by the orphan sweep below.
		v4IPs, v6IPs := splitByFamily(pair.DstIPs)
		families := []struct {
			label, suffix, tmlType, ipVersion, srcTMLID string
			dstIPs                                      []string
		}{
			{"IPv4", "-v4", "IPV4_ADDRESSES", "IPV4", tmlV4.ID, v4IPs},
			{"IPv6", "-v6", "IPV6_ADDRESSES", "IPV6", tmlV6.ID, v6IPs},
		}
		var pairPolicyIDs []string
		for _, f := range families {
			if len(pair.DstIPs) > 0 && len(f.dstIPs) == 0 {
				continue
			}
			var dstIPTMLID string
			if len(f.dstIPs) > 0 {
				name := whitelistName("dstips-", pair, f.suffix)
				t, ipErr := m.ensureTML(ctx, site, name, f.tmlType, ipsToItems(f.dstIPs))
				if ipErr != nil {
					return fmt.Errorf("ensure destination %s TML for %s->%s: %w", f.label, pair.SrcName, pair.DstName, ipErr)
				}
				dstIPTMLID = t.ID
				expectedTMLNames[name] = true
			}
			policyName := whitelistName("", pair, f.suffix)
			p, err := m.ensureAllowPolicy(ctx, site, pair, f.srcTMLID, srcPortTMLID, dstPortTMLID, dstIPTMLID, f.ipVersion, policyName, existingPolicies)
			if err != nil {
				return fmt.Errorf("ensure %s allow policy for %s->%s: %w", f.label, pair.SrcName, pair.DstName, err)
			}
			managedPolicyIDs[p.ID] = true
			pairPolicyIDs = append(pairPolicyIDs, p.ID)
		}

		// Verify that the controller evaluates the allow policies before blocks.
		// A wrong order is reported once every pair is ensured and the sweeps
		// have run: it needs the block recreated, and stale policies must not
		// outlive it.
		if err := m.checkWhitelistOrder(ctx, site, pair, pairPolicyIDs); err != nil {
			orderErrs = append(orderErrs, err)
		}
	}

	// Sweep a fresh listing: policies recreated above may have taken the IDs of
	// the ones they replaced.
	current, err := m.ctrl.ListZonePolicies(ctx, site)
	if err != nil {
		return errors.Join(append(orderErrs, fmt.Errorf("list zone policies for site %s: %w", site, err))...)
	}
	m.sweepOrphanPolicies(ctx, site, current, managedPolicyIDs)
	m.sweepOrphanTMLs(ctx, site, expectedTMLNames)
	return errors.Join(orderErrs...)
}

// sweepOrphanPolicies deletes whitelist policies that are ours but no longer
// declared in CLOUDFLARE_ZONE_PAIRS. managedIDs are the forward policies just
// ensured.
func (m *Manager) sweepOrphanPolicies(ctx context.Context, site string, existing []controller.ZonePolicy,
	managedIDs map[string]bool) {
	deletable := deletableWhitelistPolicies(existing)
	for _, p := range existing {
		// Keep only the exact IDs just ensured. ID-based tracking handles
		// duplicate-named policies: only the one ensureAllowPolicy returned is kept.
		if !deletable[p.ID] || managedIDs[p.ID] {
			continue
		}
		if err := m.ctrl.DeleteZonePolicy(ctx, site, p.ID); err != nil {
			m.log.Warn().Err(err).Str("policy", p.Name).Msg("failed to delete orphaned whitelist policy")
		} else {
			m.log.Info().Str("policy", p.Name).Str("site", site).
				Msg("deleted orphaned Cloudflare whitelist policy (zone pair removed from config)")
		}
	}
}

// deletableWhitelistPolicies returns the IDs of the listed whitelist policies
// the bouncer may delete: forward policies carrying its description, and
// "(Return)" mirrors whose base is no longer listed. UniFi derives a mirror
// from every ALLOW policy with AllowReturnTraffic=true, refuses to delete it
// while its base exists (derived-firewall-policy-deletion-forbidden), and
// removes it together with its base.
func deletableWhitelistPolicies(policies []controller.ZonePolicy) map[string]bool {
	listed := make(map[string]bool, len(policies))
	for _, p := range policies {
		listed[p.Name] = true
	}
	deletable := make(map[string]bool)
	for _, p := range policies {
		if !strings.HasPrefix(p.Name, whitelistPrefix) {
			continue
		}
		if base, isReturn := strings.CutSuffix(p.Name, " (Return)"); isReturn {
			deletable[p.ID] = !listed[base]
			continue
		}
		deletable[p.ID] = p.Description == whitelistDescription
	}
	return deletable
}

// sweepOrphanTMLs deletes per-pair filter TMLs (srcports, dstports, dstips)
// whose name is not in expected. The shared Cloudflare IP TMLs are never
// touched here.
func (m *Manager) sweepOrphanTMLs(ctx context.Context, site string, expected map[string]bool) {
	allTMLs, err := m.ctrl.ListTrafficMatchingLists(ctx, site)
	if err != nil {
		m.log.Warn().Err(err).Str("site", site).Msg("failed to list TMLs for orphan sweep")
		return
	}
	for _, t := range allTMLs {
		if !strings.HasPrefix(t.Name, whitelistPrefix) {
			continue
		}
		if !strings.Contains(t.Name, "srcports-") && !strings.Contains(t.Name, "dstports-") && !strings.Contains(t.Name, "dstips-") {
			continue
		}
		if expected[t.Name] {
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

			// A PUT carries no port or destination filters and the controller drops
			// them, so a filtered policy is recreated rather than updated. Recreating
			// also clears any connection state filter.
			filtered := srcPortTMLID != "" || dstPortTMLID != "" || dstIPTMLID != ""
			filterChanging := p.SrcPortTMLID != srcPortTMLID || p.DstPortTMLID != dstPortTMLID || p.DstIPTMLID != dstIPTMLID || len(p.ConnectionStateFilter) > 0
			if filtered || filterChanging {
				m.log.Info().Str("policy", policyName).Str("site", site).
					Msg("filtered policy drifted — deleting for recreation")
				if delErr := m.ctrl.DeleteZonePolicy(ctx, site, p.ID); delErr != nil {
					return controller.ZonePolicy{}, fmt.Errorf("delete policy %s before filter recreation: %w", policyName, delErr)
				}
				// Fall through to the creation path below.
				break
			}

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

// checkWhitelistOrder makes sure no block takes precedence over a Cloudflare
// allow. Integration-created policies cannot be moved with the user-defined
// policy ordering endpoint, and the controller evaluates them in creation
// order, so an allow added to a pair whose blocks already exist lands behind
// them. Those blocks are recreated, which moves them behind the allow, and the
// order is checked again.
func (m *Manager) checkWhitelistOrder(ctx context.Context, site string, pair ZonePairConfig, policyIDs []string) error {
	wrong, err := m.blocksAheadOfAllow(ctx, site, pair, policyIDs)
	if err != nil || len(wrong) == 0 || m.blocks == nil {
		return orderError(site, wrong, err)
	}
	ids := make([]string, 0, len(wrong))
	seen := make(map[string]bool, len(wrong))
	for _, w := range wrong {
		if !seen[w.block.ID] {
			seen[w.block.ID] = true
			ids = append(ids, w.block.ID)
		}
	}
	m.log.Info().Int("blocks", len(ids)).Str("site", site).Str("pair", pair.SrcName+"->"+pair.DstName).
		Msg("block policies precede the Cloudflare allow; recreating them")
	if err := m.blocks.RecreatePolicies(ctx, site, ids); err != nil {
		m.log.Warn().Err(err).Str("site", site).Msg("could not recreate every block policy that precedes the Cloudflare allow")
	}
	wrong, err = m.blocksAheadOfAllow(ctx, site, pair, policyIDs)
	return orderError(site, wrong, err)
}

// misorderedBlock is a block policy the controller evaluates before an allow.
type misorderedBlock struct {
	allow, block controller.ZonePolicy
}

func orderError(site string, wrong []misorderedBlock, err error) error {
	if err != nil || len(wrong) == 0 {
		return err
	}
	w := wrong[0]
	return fmt.Errorf("cloudflare allow policy %s follows block %s in site %s; recreate the block after the allow policy", w.allow.Name, w.block.Name, site)
}

// blocksAheadOfAllow lists the enabled blocks of pair's zones and address
// family that the controller evaluates before one of the allows in policyIDs.
func (m *Manager) blocksAheadOfAllow(ctx context.Context, site string, pair ZonePairConfig, policyIDs []string) ([]misorderedBlock, error) {
	policies, err := m.ctrl.ListZonePolicies(ctx, site)
	if err != nil {
		return nil, fmt.Errorf("list policies to verify Cloudflare order in site %s: %w", site, err)
	}
	byID := make(map[string]controller.ZonePolicy, len(policies))
	for _, p := range policies {
		byID[p.ID] = p
	}
	var wrong []misorderedBlock
	for _, id := range policyIDs {
		allow, found := byID[id]
		if !found {
			return nil, fmt.Errorf("cloudflare allow policy %s missing from site %s after sync", id, site)
		}
		for _, p := range policies {
			if !p.Enabled || p.Action != "BLOCK" || p.SrcZone != pair.SrcZoneID || p.DstZone != pair.DstZoneID {
				continue
			}
			if p.IPVersion != "" && p.IPVersion != "BOTH" && p.IPVersion != allow.IPVersion {
				continue
			}
			if allow.Index == nil || p.Index == nil {
				// The controller did not report an order, so it cannot be
				// checked. That is not evidence of a wrong order.
				m.log.Warn().Str("allow", allow.Name).Str("block", p.Name).Str("site", site).
					Msg("cannot verify Cloudflare allow precedes block: controller did not report policy order")
				continue
			}
			if *p.Index <= *allow.Index {
				wrong = append(wrong, misorderedBlock{allow: allow, block: p})
			}
		}
	}
	return wrong, nil
}

// Drain removes all Cloudflare whitelist policies and TMLs from all managed
// sites. Call when CLOUDFLARE_WHITELIST_ENABLED is set to false so that
// previously-created objects are cleaned up rather than left as orphans.
// The provider is not used — no live Cloudflare IPs are fetched.
func (m *Manager) Drain(ctx context.Context) error {
	return m.drain(ctx, false)
}

// PreviewDrain logs the policies and lists Drain would delete without
// deleting them.
func (m *Manager) PreviewDrain(ctx context.Context) error {
	return m.drain(ctx, true)
}

func (m *Manager) drain(ctx context.Context, dryRun bool) error {
	var failed []error
	for _, site := range m.sites {
		policies, err := m.ctrl.ListZonePolicies(ctx, site)
		if err != nil {
			m.log.Warn().Err(err).Str("site", site).Msg("Cloudflare drain: failed to list zone policies")
			failed = append(failed, fmt.Errorf("list zone policies for site %s: %w", site, err))
		} else {
			deletable := deletableWhitelistPolicies(policies)
			for _, p := range policies {
				if !deletable[p.ID] {
					continue
				}
				if dryRun {
					m.log.Info().Str("policy", p.Name).Str("site", site).
						Msg("[DRY-RUN] Cloudflare drain: would delete whitelist policy")
					continue
				}
				if err := m.ctrl.DeleteZonePolicy(ctx, site, p.ID); err != nil {
					m.log.Warn().Err(err).Str("policy", p.Name).Str("site", site).
						Msg("Cloudflare drain: failed to delete whitelist policy")
					failed = append(failed, fmt.Errorf("delete whitelist policy %s: %w", p.Name, err))
				} else {
					m.log.Info().Str("policy", p.Name).Str("site", site).
						Msg("Cloudflare drain: deleted whitelist policy")
				}
			}
		}

		tmls, err := m.ctrl.ListTrafficMatchingLists(ctx, site)
		if err != nil {
			m.log.Warn().Err(err).Str("site", site).Msg("Cloudflare drain: failed to list TMLs")
			failed = append(failed, fmt.Errorf("list traffic matching lists for site %s: %w", site, err))
		} else {
			for _, t := range tmls {
				if !strings.HasPrefix(t.Name, whitelistPrefix) {
					continue
				}
				if dryRun {
					m.log.Info().Str("tml", t.Name).Str("site", site).
						Msg("[DRY-RUN] Cloudflare drain: would delete whitelist TML")
					continue
				}
				if err := m.ctrl.DeleteTrafficMatchingList(ctx, site, t.ID); err != nil {
					m.log.Warn().Err(err).Str("tml", t.Name).Str("site", site).
						Msg("Cloudflare drain: failed to delete whitelist TML")
					failed = append(failed, fmt.Errorf("delete whitelist list %s: %w", t.Name, err))
				} else {
					m.log.Info().Str("tml", t.Name).Str("site", site).
						Msg("Cloudflare drain: deleted whitelist TML")
				}
			}
		}
	}
	return errors.Join(failed...)
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

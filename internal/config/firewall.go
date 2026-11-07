package config

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// ParseFirewallConnectionStates returns the zone block policy state filter.
// ALL preserves UniFi's unrestricted-state behavior for installations that
// intentionally want to block established and related traffic as well.
func (c *Config) ParseFirewallConnectionStates() ([]string, error) {
	return parseConnectionStates("FIREWALL_CONNECTION_STATES", c.FirewallConnectionStates)
}

// ParseEgressConnectionStates returns the state filter of egress block
// policies. The default, NEW, leaves replies to allowed inbound connections
// untouched.
func (c *Config) ParseEgressConnectionStates() ([]string, error) {
	return parseConnectionStates("EGRESS_CONNECTION_STATES", c.EgressConnectionStates)
}

func parseConnectionStates(setting, value string) ([]string, error) {
	raw := strings.TrimSpace(value)
	if strings.EqualFold(raw, "ALL") {
		return nil, nil
	}
	if raw == "" {
		return nil, fmt.Errorf("%s must be ALL or a comma-separated list of NEW,INVALID,ESTABLISHED", setting)
	}
	allowed := map[string]bool{"NEW": true, "INVALID": true, "ESTABLISHED": true}
	seen := make(map[string]bool)
	var states []string
	for _, part := range strings.Split(raw, ",") {
		state := strings.ToUpper(stripEnvQuotes(strings.TrimSpace(part)))
		if !allowed[state] || seen[state] {
			return nil, fmt.Errorf("%s contains invalid or duplicate state %q", setting, part)
		}
		seen[state] = true
		states = append(states, state)
	}
	return states, nil
}

// validateFirewall checks the firewall mode, block action, connection state
// filter, object name templates, and zone pairs.
func (c *Config) validateFirewall() error {
	validModes := map[string]bool{"auto": true, "legacy": true, "zone": true}
	if !validModes[c.FirewallMode] {
		return fmt.Errorf("FIREWALL_MODE must be auto, legacy, or zone; got %q", c.FirewallMode)
	}
	// Zone policies and traffic matching lists live on the integration API,
	// which accepts API keys only.
	if c.FirewallMode == "zone" && c.UnifiAPIKey == "" {
		return fmt.Errorf("FIREWALL_MODE=zone requires UNIFI_API_KEY; a username and password can only manage legacy firewall rules")
	}

	validActions := map[string]bool{"drop": true, "reject": true}
	if !validActions[c.FirewallBlockAction] {
		return fmt.Errorf("FIREWALL_BLOCK_ACTION must be drop or reject; got %q", c.FirewallBlockAction)
	}
	if _, err := c.ParseFirewallConnectionStates(); err != nil {
		return err
	}
	if err := c.validateEgress(); err != nil {
		return err
	}
	if c.FirewallMode != "zone" {
		if err := c.validateLegacy(); err != nil {
			return err
		}
	}

	for _, pair := range []struct{ name, tmpl string }{
		{"GROUP_NAME_TEMPLATE", c.GroupNameTemplate},
		{"RULE_NAME_TEMPLATE", c.RuleNameTemplate},
		{"POLICY_NAME_TEMPLATE", c.PolicyNameTemplate},
	} {
		if err := validateNameTemplate(pair.name, pair.tmpl); err != nil {
			return err
		}
	}
	if err := c.checkLegacyGroupNames(); err != nil {
		return err
	}

	// Validate zone pairs if mode is zone or auto
	if c.FirewallMode != "legacy" {
		pairs, err := c.ParseZonePairs()
		if err != nil {
			return fmt.Errorf("ZONE_PAIRS: %w", err)
		}
		// With no pairs, every block policy the bouncer manages would be
		// treated as belonging to a removed pair and deleted.
		if c.FirewallMode == "zone" && len(pairs) == 0 {
			return fmt.Errorf("ZONE_PAIRS must name at least one src->dst zone pair when FIREWALL_MODE=zone")
		}
		if err := checkDuplicatePairs("ZONE_PAIRS", pairs); err != nil {
			return err
		}
	}
	return nil
}

// checkLegacyGroupNames checks the length of the legacy group names
// GROUP_NAME_TEMPLATE renders. Too long a name is an error with
// FIREWALL_MODE=legacy and a warning with auto, where the sites that resolve
// to the zone-based firewall name traffic matching lists instead, which take
// longer names. Zone mode is not checked.
func (c *Config) checkLegacyGroupNames() error {
	if c.FirewallMode == "zone" {
		return nil
	}
	sites := c.UnifiSites
	if c.UnifiSitesAuto || len(sites) == 0 {
		sites = []string{"default"}
	}
	tooLong, err := legacyGroupNameTooLong(c.GroupNameTemplate, sites)
	if err != nil || tooLong == "" {
		return err
	}
	if c.FirewallMode == "legacy" {
		return errors.New(tooLong)
	}
	c.DeprecationWarnings = append(c.DeprecationWarnings,
		tooLong+"; sites on the legacy firewall will fail to create that group")
	return nil
}

// legacyRulesetsV4 and legacyRulesetsV6 are the rulesets the classic firewall
// API accepts for each address family.
var (
	legacyRulesetsV4 = []string{
		"WAN_IN", "WAN_OUT", "WAN_LOCAL", "LAN_IN", "LAN_OUT", "LAN_LOCAL", "GUEST_IN", "GUEST_OUT", "GUEST_LOCAL",
	}
	legacyRulesetsV6 = []string{
		"WANv6_IN", "WANv6_OUT", "WANv6_LOCAL", "LANv6_IN", "LANv6_OUT", "LANv6_LOCAL", "GUESTv6_IN", "GUESTv6_OUT", "GUESTv6_LOCAL",
	}
)

// maxLegacyRuleIndex is the highest rule index the legacy settings accept.
// Shards take consecutive indexes from the start value.
const maxLegacyRuleIndex = 99999

// validateLegacy checks the legacy rule settings, which apply with
// FIREWALL_MODE=legacy and to sites that auto mode resolves to legacy.
func (c *Config) validateLegacy() error {
	for _, rs := range []struct {
		name, value string
		allowed     []string
	}{
		{"LEGACY_RULESET_V4", c.LegacyRulesetV4, legacyRulesetsV4},
		{"LEGACY_RULESET_V6", c.LegacyRulesetV6, legacyRulesetsV6},
	} {
		if !slices.Contains(rs.allowed, rs.value) {
			return fmt.Errorf("%s must be one of %s; got %q", rs.name, strings.Join(rs.allowed, ","), rs.value)
		}
	}
	for _, idx := range []struct {
		name  string
		value int
	}{
		{"LEGACY_RULE_INDEX_START_V4", c.LegacyRuleIndexStartV4},
		{"LEGACY_RULE_INDEX_START_V6", c.LegacyRuleIndexStartV6},
	} {
		if idx.value < 1 || idx.value > maxLegacyRuleIndex {
			return fmt.Errorf("%s must be between 1 and %d; got %d", idx.name, maxLegacyRuleIndex, idx.value)
		}
	}
	return nil
}

// validateEgress checks EGRESS_ZONE_PAIRS and EGRESS_CONNECTION_STATES. Egress
// policies are zone policies, so they need the zone-based firewall and the
// integration API.
func (c *Config) validateEgress() error {
	if _, err := c.ParseEgressConnectionStates(); err != nil {
		return err
	}
	pairs, err := c.ParseEgressZonePairs()
	if err != nil {
		return fmt.Errorf("EGRESS_ZONE_PAIRS: %w", err)
	}
	if len(pairs) == 0 {
		return nil
	}
	if c.FirewallMode == "legacy" {
		return fmt.Errorf("EGRESS_ZONE_PAIRS needs the zone-based firewall; it cannot be used with FIREWALL_MODE=legacy")
	}
	if c.UnifiAPIKey == "" {
		return fmt.Errorf("EGRESS_ZONE_PAIRS requires UNIFI_API_KEY; zone policies are managed through the integration API")
	}
	return checkDuplicatePairs("EGRESS_ZONE_PAIRS", pairs)
}

// checkDuplicatePairs rejects a src->dst pair that setting names twice for
// one site. A pair's policies and filter lists are named after its zones, so
// a second pair with the same zones, even with other ports, would overwrite
// the first. A site's own pairs replace the unprefixed ones, so a pair may
// appear once without a prefix and again for a site.
func checkDuplicatePairs(setting string, pairs []ZonePair) error {
	seen := make(map[string]bool, len(pairs))
	for _, p := range pairs {
		zones := p.Src + "->" + p.Dst
		key := p.Site + "/" + zones
		if seen[key] {
			if p.Site != "" {
				return fmt.Errorf("%s names %s more than once for site %q", setting, zones, p.Site)
			}
			return fmt.Errorf("%s names %s more than once", setting, zones)
		}
		seen[key] = true
	}
	return nil
}

// validateCloudflare checks the Cloudflare whitelist config when enabled.
func (c *Config) validateCloudflare() error {
	if !c.CloudflareWhitelistEnabled {
		return nil
	}
	// The whitelist is a set of zone policies managed through the
	// integration API, which accepts API keys only.
	if c.FirewallMode == "legacy" {
		return fmt.Errorf("CLOUDFLARE_WHITELIST_ENABLED requires the zone-based firewall; it cannot be used with FIREWALL_MODE=legacy")
	}
	if c.UnifiAPIKey == "" {
		return fmt.Errorf("CLOUDFLARE_WHITELIST_ENABLED requires UNIFI_API_KEY")
	}
	if c.CloudflareRefreshInterval <= 0 {
		return fmt.Errorf("CLOUDFLARE_REFRESH_INTERVAL must be > 0")
	}
	if len(c.CloudflareZonePairs) == 0 {
		return fmt.Errorf("CLOUDFLARE_WHITELIST_ENABLED is set but CLOUDFLARE_ZONE_PAIRS is empty")
	}
	cloudflarePairs, err := c.ParseCloudflareZonePairs()
	if err != nil {
		return fmt.Errorf("CLOUDFLARE_ZONE_PAIRS: %w", err)
	}
	if err := checkDuplicatePairs("CLOUDFLARE_ZONE_PAIRS", cloudflarePairs); err != nil {
		return err
	}
	if !isHTTPSURL(c.CloudflareIPv4URL) || !isHTTPSURL(c.CloudflareIPv6URL) {
		return fmt.Errorf("CLOUDFLARE_IPV4_URL and CLOUDFLARE_IPV6_URL must be absolute https:// URLs")
	}
	return nil
}

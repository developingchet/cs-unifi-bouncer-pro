package config

import (
	"fmt"
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
		state := strings.ToUpper(strings.TrimSpace(part))
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

	for _, pair := range []struct{ name, tmpl string }{
		{"GROUP_NAME_TEMPLATE", c.GroupNameTemplate},
		{"RULE_NAME_TEMPLATE", c.RuleNameTemplate},
		{"POLICY_NAME_TEMPLATE", c.PolicyNameTemplate},
	} {
		if err := validateNameTemplate(pair.name, pair.tmpl); err != nil {
			return err
		}
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
	// A site's own pairs replace the unprefixed ones, so a pair may appear
	// once without a prefix and again for a site.
	seen := make(map[string]bool, len(pairs))
	for _, p := range pairs {
		zones := p.Src + "->" + p.Dst
		key := p.Site + "/" + zones
		if seen[key] {
			if p.Site != "" {
				return fmt.Errorf("EGRESS_ZONE_PAIRS names %s more than once for site %q", zones, p.Site)
			}
			return fmt.Errorf("EGRESS_ZONE_PAIRS names %s more than once", zones)
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
	if _, err := c.ParseCloudflareZonePairs(); err != nil {
		return fmt.Errorf("CLOUDFLARE_ZONE_PAIRS: %w", err)
	}
	if !isHTTPSURL(c.CloudflareIPv4URL) || !isHTTPSURL(c.CloudflareIPv6URL) {
		return fmt.Errorf("CLOUDFLARE_IPV4_URL and CLOUDFLARE_IPV6_URL must be absolute https:// URLs")
	}
	return nil
}

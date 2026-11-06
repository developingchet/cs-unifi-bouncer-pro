package config

import (
	"fmt"
	"slices"
	"strings"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/decision"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/webhook"
)

// validateFeeds checks the blocklist import and webhook notification settings.
func (c *Config) validateFeeds() error {
	if len(c.BlocklistURLs) > 0 && c.BlocklistRefreshInterval <= 0 {
		return fmt.Errorf("BLOCKLIST_REFRESH_INTERVAL must be > 0 when BLOCKLIST_URLS is set")
	}
	// Entries are named by position, never echoed: these URLs often carry tokens.
	for i, raw := range c.BlocklistURLs {
		if !isHTTPURL(raw) {
			return fmt.Errorf("BLOCKLIST_URLS entry %d must be an absolute http:// or https:// URL", i+1)
		}
	}
	if c.BlocklistMinPrefixV4 < decision.DefaultMinRangePrefixV4 || c.BlocklistMinPrefixV4 > 32 {
		return fmt.Errorf("BLOCKLIST_MIN_PREFIX_V4 must be between %d and 32; got %d", decision.DefaultMinRangePrefixV4, c.BlocklistMinPrefixV4)
	}
	if c.BlocklistMinPrefixV6 < decision.DefaultMinRangePrefixV6 || c.BlocklistMinPrefixV6 > 128 {
		return fmt.Errorf("BLOCKLIST_MIN_PREFIX_V6 must be between %d and 128; got %d", decision.DefaultMinRangePrefixV6, c.BlocklistMinPrefixV6)
	}
	if err := c.validateAbuseIPDB(); err != nil {
		return err
	}
	if c.WebhookURL != "" && !isHTTPURL(c.WebhookURL) {
		return fmt.Errorf("WEBHOOK_URL must be an absolute http:// or https:// URL")
	}
	for _, event := range c.WebhookEvents {
		if !slices.Contains(webhook.Events, event) {
			return fmt.Errorf("WEBHOOK_EVENTS: unknown event %q; valid events are %s", event, strings.Join(webhook.Events, ", "))
		}
	}
	return nil
}

// AbuseIPDBLists are the list names borestad/blocklist-abuseipdb publishes,
// by how many days of reports each covers.
var AbuseIPDBLists = []string{"1d", "3d", "7d", "14d", "30d", "60d", "90d", "120d", "180d", "365d"}

// abuseIPDBNeedsFilter are the lists too large to import whole: over the
// 250,000-entry feed limit. They need ABUSEIPDB_COUNTRY_INCLUDE.
var abuseIPDBNeedsFilter = []string{"120d", "180d", "365d"}

// AbuseIPDBURL returns the raw URL of the configured AbuseIPDB list, or ""
// when the feed is off.
func (c *Config) AbuseIPDBURL() string {
	if c.AbuseIPDBList == "" {
		return ""
	}
	if c.AbuseIPDBURLOverride != "" {
		return c.AbuseIPDBURLOverride
	}
	return "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/main/abuseipdb-s100-" + c.AbuseIPDBList + ".ipv4"
}

// validateAbuseIPDB checks the AbuseIPDB list name and country filters.
func (c *Config) validateAbuseIPDB() error {
	if c.AbuseIPDBList == "" {
		if len(c.AbuseIPDBCountryInclude) > 0 || len(c.AbuseIPDBCountryExclude) > 0 || c.AbuseIPDBURLOverride != "" {
			return fmt.Errorf("ABUSEIPDB_URL/ABUSEIPDB_COUNTRY_INCLUDE/ABUSEIPDB_COUNTRY_EXCLUDE need ABUSEIPDB_LIST to be set")
		}
		return nil
	}
	if c.AbuseIPDBURLOverride != "" && !isHTTPURL(c.AbuseIPDBURLOverride) {
		return fmt.Errorf("ABUSEIPDB_URL must be an absolute http:// or https:// URL")
	}
	if !slices.Contains(AbuseIPDBLists, c.AbuseIPDBList) {
		return fmt.Errorf("ABUSEIPDB_LIST: unknown list %q; valid lists are %s", c.AbuseIPDBList, strings.Join(AbuseIPDBLists, ", "))
	}
	if c.AbuseIPDBRefreshInterval <= 0 {
		return fmt.Errorf("ABUSEIPDB_REFRESH_INTERVAL must be > 0 when ABUSEIPDB_LIST is set")
	}
	for _, list := range []struct {
		name  string
		codes []string
	}{
		{"ABUSEIPDB_COUNTRY_INCLUDE", c.AbuseIPDBCountryInclude},
		{"ABUSEIPDB_COUNTRY_EXCLUDE", c.AbuseIPDBCountryExclude},
	} {
		for _, code := range list.codes {
			if !isCountryCode(code) {
				return fmt.Errorf("%s: %q is not a two-letter country code", list.name, code)
			}
		}
	}
	for _, code := range c.AbuseIPDBCountryInclude {
		if slices.Contains(c.AbuseIPDBCountryExclude, code) {
			return fmt.Errorf("country %s is in both ABUSEIPDB_COUNTRY_INCLUDE and ABUSEIPDB_COUNTRY_EXCLUDE", code)
		}
	}
	if slices.Contains(abuseIPDBNeedsFilter, c.AbuseIPDBList) && len(c.AbuseIPDBCountryInclude) == 0 {
		return fmt.Errorf("ABUSEIPDB_LIST=%s is over the 250000-entry feed limit; set ABUSEIPDB_COUNTRY_INCLUDE or pick a list of 90d or shorter", c.AbuseIPDBList)
	}
	return nil
}

func isCountryCode(s string) bool {
	return len(s) == 2 && s[0] >= 'A' && s[0] <= 'Z' && s[1] >= 'A' && s[1] <= 'Z'
}

// splitCountryCodes parses a CSV of country codes, upper-cased and deduplicated.
func splitCountryCodes(s string) []string {
	var codes []string
	for _, code := range splitCSV(stripEnvQuotes(strings.TrimSpace(s))) {
		code = strings.ToUpper(stripEnvQuotes(code))
		if !slices.Contains(codes, code) {
			codes = append(codes, code)
		}
	}
	return codes
}

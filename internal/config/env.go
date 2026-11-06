package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/decision"
	"github.com/knadh/koanf/v2"
)

// unquoteValues removes a single layer of matching surrounding quotes from
// every setting, as Docker's --env-file passes shell quoting through. It runs
// before list settings are split, so CROWDSEC_ORIGINS="crowdsec,lists" keeps
// both origins whole instead of becoming `"crowdsec` and `lists"`.
func unquoteValues(k *koanf.Koanf) error {
	for key, value := range k.All() {
		s, ok := value.(string)
		if !ok {
			continue
		}
		if unquoted := stripEnvQuotes(s); unquoted != s {
			if err := k.Set(key, unquoted); err != nil {
				return fmt.Errorf("unquote %s: %w", strings.ToUpper(key), err)
			}
		}
	}
	return nil
}

// sanitise removes a single layer of matching surrounding quotes from each
// element of the list settings, for lists written as 'a','b'. Whole values
// are unquoted before they are split (see unquoteValues).
func (c *Config) sanitise() {
	c.AbuseIPDBList = strings.ToLower(strings.TrimSpace(c.AbuseIPDBList))

	for _, list := range [][]string{
		c.UnifiSites, c.UnifiSitesExclude, c.CrowdSecOrigins, c.BlockWhitelist, c.BlockScenarioExclude,
		c.ZonePairs, c.CloudflareZonePairs, c.EgressZonePairs, c.BlocklistURLs, c.WebhookEvents,
	} {
		for i, s := range list {
			list[i] = stripEnvQuotes(s)
		}
	}
}

// defaults sets sensible default values.
func defaults() map[string]interface{} {
	return map[string]interface{}{
		"unifi_verify_tls":               true,
		"unifi_http_timeout":             "120s",
		"unifi_sites":                    "default",
		"firewall_mode":                  "auto",
		"firewall_block_action":          "drop",
		"firewall_enable_ipv6":           true,
		"firewall_api_shard_delay":       "250ms",
		"firewall_connection_states":     "NEW,INVALID",
		"egress_connection_states":       "NEW",
		"firewall_reconcile_on_start":    true,
		"firewall_reconcile_interval":    "10m",
		"sync_interval":                  "30s",
		"shard_limit":                    10000,
		"shard_merge_threshold":          0,
		"group_name_template":            "crowdsec-block-{{.Family}}-{{.Index}}",
		"rule_name_template":             "crowdsec-drop-{{.Family}}-{{.Index}}",
		"policy_name_template":           "crowdsec-policy-{{.SrcZone}}-{{.DstZone}}-{{.Family}}-{{.Index}}",
		"object_description":             "Managed by cs-unifi-bouncer-pro. Do not edit manually.",
		"legacy_rule_index_start_v4":     22000,
		"legacy_rule_index_start_v6":     27000,
		"legacy_ruleset_v4":              "WAN_IN",
		"legacy_ruleset_v6":              "WANv6_IN",
		"zone_pairs":                     "External->Dmz",
		"circuit_breaker_threshold":      5,
		"circuit_breaker_reset_interval": "60s",
		"cloudflare_whitelist_enabled":   false,
		"cloudflare_refresh_interval":    "168h",
		"cloudflare_ipv4_url":            "https://www.cloudflare.com/ips-v4",
		"cloudflare_ipv6_url":            "https://www.cloudflare.com/ips-v6",
		"crowdsec_lapi_url":              "https://crowdsec:8080",
		"crowdsec_lapi_verify_tls":       true,
		"crowdsec_lapi_allow_http":       false,
		"crowdsec_poll_interval":         "30s",
		"crowdsec_resync_interval":       "1h",
		"lapi_metrics_push_interval":     "30m",
		"session_reauth_min_gap":         "5s",
		"session_reauth_timeout":         "10s",
		"data_dir":                       "/data",
		"ban_ttl":                        "168h",
		"log_level":                      "info",
		"log_format":                     "json",
		"metrics_enabled":                true,
		"metrics_addr":                   ":9090",
		"health_addr":                    defaultHealthAddr,
		"janitor_interval":               "1h",
		"shutdown_grace_period":          "30s",
		"health_check_lapi":              true,
		"history_max_events":             10000,
		"blocklist_refresh_interval":     "24h",
		"blocklist_min_prefix_v4":        decision.DefaultMinRangePrefixV4,
		"blocklist_min_prefix_v6":        decision.DefaultMinRangePrefixV6,
		"abuseipdb_refresh_interval":     "6h",
		"decision_rate_limit":            0,
		"decision_burst_size":            1000,
		"unifi_require_https":            true,
		"unifi_sites_auto":               false,
	}
}

const defaultHealthAddr = ":8081"

// HealthAddrFromEnv returns HEALTH_ADDR without loading the rest of the
// configuration, so the healthcheck subcommand also works where the other
// settings are not in its environment (a systemd EnvironmentFile).
func HealthAddrFromEnv() string {
	if addr := stripEnvQuotes(strings.TrimSpace(os.Getenv("HEALTH_ADDR"))); addr != "" {
		return addr
	}
	return defaultHealthAddr
}

// stripEnvQuotes removes a single layer of matching surrounding single or double
// quotes from s. This normalises values set via Docker --env-file, which does not
// strip shell quoting. Only symmetric pairs are stripped: 'x' → x, "x" → x.
// Unpaired or mismatched quotes are left as-is.
func stripEnvQuotes(s string) string {
	if len(s) < 2 {
		return s
	}
	if (s[0] == '\'' && s[len(s)-1] == '\'') ||
		(s[0] == '"' && s[len(s)-1] == '"') {
		return s[1 : len(s)-1]
	}
	return s
}

// fileSecretKeys may be read from the file named by <NAME>_FILE, for Docker
// and Kubernetes secrets. The file's contents are trimmed.
var fileSecretKeys = []string{
	"unifi_username",
	"unifi_password",
	"unifi_api_key",
	"crowdsec_lapi_key",
}

// fileZonePairKeys may also be read from a file. Load runs again on SIGHUP, so
// pairs kept in a mounted file (a bind mount or a Kubernetes ConfigMap) can
// change without a restart, which the process environment cannot.
var fileZonePairKeys = []string{
	"zone_pairs",
	"egress_zone_pairs",
}

// injectFileSettings replaces each setting that has a <NAME>_FILE variable
// with the contents of that file.
func injectFileSettings(k *koanf.Koanf) error {
	for _, key := range fileSecretKeys {
		if err := injectFileSetting(k, key, strings.TrimSpace); err != nil {
			return err
		}
	}
	for _, key := range fileZonePairKeys {
		if err := injectFileSetting(k, key, joinZonePairLines); err != nil {
			return err
		}
	}
	return nil
}

func injectFileSetting(k *koanf.Koanf, key string, parse func(string) string) error {
	filePath := k.String(key + "_file")
	if filePath == "" {
		filePath = os.Getenv(strings.ToUpper(key) + "_FILE")
	}
	if filePath == "" {
		return nil
	}
	// Docker's --env-file keeps quotes around the path.
	filePath = stripEnvQuotes(filePath)
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("%s_FILE: cannot read %s: %w", strings.ToUpper(key), filePath, err)
	}
	if err := k.Set(key, parse(string(content))); err != nil {
		return fmt.Errorf("setting %s from file: %w", key, err)
	}
	return nil
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// parseScenarioDurationMap parses comma- or semicolon-separated scenario durations.
// Example: "ssh-bf=168h;http-probing=24h". Returns nil on empty input.
func parseScenarioDurationMap(s string) (map[string]time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	result := make(map[string]time.Duration)
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' }) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, valStr, found := strings.Cut(part, "=")
		key = strings.TrimSpace(key)
		valStr = strings.TrimSpace(valStr)
		if !found || key == "" || valStr == "" {
			return nil, fmt.Errorf("entry %q must be scenario=duration", part)
		}
		d, err := time.ParseDuration(valStr)
		if err != nil || d <= 0 {
			return nil, fmt.Errorf("entry %q must use a positive duration such as 24h", part)
		}
		result[key] = d
	}
	return result, nil
}

// rawProvider implements koanf.Provider for a map[string]interface{}.
type rawProvider struct {
	data map[string]interface{}
}

// Read returns the config map directly (no Parser needed).
func (r *rawProvider) Read() (map[string]interface{}, error) {
	return r.data, nil
}

// ReadBytes is not used by rawProvider; koanf calls Read() when no Parser is given.
func (r *rawProvider) ReadBytes() ([]byte, error) {
	return nil, fmt.Errorf("rawProvider does not support ReadBytes")
}

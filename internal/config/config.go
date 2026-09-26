package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/v2"
)

// Config holds all application configuration.
type Config struct {
	// UniFi Controller Connection
	UnifiURL         string        `koanf:"unifi_url"`
	UnifiUsername    string        `koanf:"unifi_username"`
	UnifiPassword    string        `koanf:"unifi_password"`
	UnifiAPIKey      string        `koanf:"unifi_api_key"`
	UnifiVerifyTLS   bool          `koanf:"unifi_verify_tls"`
	UnifiCACert      string        `koanf:"unifi_ca_cert"`
	UnifiHTTPTimeout time.Duration `koanf:"unifi_http_timeout"`
	UnifiAPIDebug    bool          `koanf:"unifi_api_debug"`

	// UniFi Sites
	UnifiSites        []string `koanf:"unifi_sites"`
	UnifiSitesAuto    bool     `koanf:"unifi_sites_auto"`
	UnifiSitesExclude []string `koanf:"-"` // parsed from UNIFI_SITES_EXCLUDE CSV

	// UniFi Security
	UnifiRequireHTTPS bool `koanf:"unifi_require_https"`

	// Firewall Mode & Behavior
	FirewallMode              string        `koanf:"firewall_mode"`
	FirewallBlockAction       string        `koanf:"firewall_block_action"`
	FirewallEnableIPv6        bool          `koanf:"firewall_enable_ipv6"`
	EnableIPv6                bool          `koanf:"enable_ipv6"` // HTTP client IPv6 dialing
	FirewallGroupCapacity     int           `koanf:"firewall_group_capacity"`
	FirewallGroupCapacityV4   int           `koanf:"firewall_group_capacity_v4"`
	FirewallGroupCapacityV6   int           `koanf:"firewall_group_capacity_v6"`
	FirewallAPIShardDelay     time.Duration `koanf:"firewall_api_shard_delay"`
	FirewallFlushConcurrency  int           `koanf:"firewall_flush_concurrency"`
	FirewallLogDrops          bool          `koanf:"firewall_log_drops"`
	FirewallConnectionStates  string        `koanf:"firewall_connection_states"`
	FirewallReconcileOnStart  bool          `koanf:"firewall_reconcile_on_start"`
	FirewallReconcileInterval time.Duration `koanf:"firewall_reconcile_interval"`

	// Shard Management (integration v1)
	SyncInterval time.Duration `koanf:"sync_interval"`
	ShardLimit   int           `koanf:"shard_limit"`
	// ShardMergeThreshold is read from env var SHARD_MERGE_THRESHOLD.
	// 0 = auto (50% of ShardLimit). -1 = disable shard rebalancing.
	ShardMergeThreshold int `koanf:"shard_merge_threshold"`

	// Object Naming Templates
	GroupNameTemplate  string `koanf:"group_name_template"`
	RuleNameTemplate   string `koanf:"rule_name_template"`
	PolicyNameTemplate string `koanf:"policy_name_template"`
	ObjectDescription  string `koanf:"object_description"`

	// Legacy Firewall Mode
	LegacyRuleIndexStartV4 int    `koanf:"legacy_rule_index_start_v4"`
	LegacyRuleIndexStartV6 int    `koanf:"legacy_rule_index_start_v6"`
	LegacyRulesetV4        string `koanf:"legacy_ruleset_v4"`
	LegacyRulesetV6        string `koanf:"legacy_ruleset_v6"`

	// Zone-Based Firewall Mode
	ZonePairs []string `koanf:"zone_pairs"`

	// Circuit Breaker
	CircuitBreakerThreshold     int           `koanf:"circuit_breaker_threshold"`
	CircuitBreakerResetInterval time.Duration `koanf:"circuit_breaker_reset_interval"`

	// Cloudflare Whitelist
	CloudflareWhitelistEnabled bool          `koanf:"cloudflare_whitelist_enabled"`
	CloudflareRefreshInterval  time.Duration `koanf:"cloudflare_refresh_interval"`
	CloudflareIPv4URL          string        `koanf:"cloudflare_ipv4_url"`
	CloudflareIPv6URL          string        `koanf:"cloudflare_ipv6_url"`
	CloudflareZonePairs        []string      `koanf:"cloudflare_zone_pairs"`

	// CrowdSec Decision Filtering
	CrowdSecLAPIURL         string        `koanf:"crowdsec_lapi_url"`
	CrowdSecLAPIKey         string        `koanf:"crowdsec_lapi_key"`
	CrowdSecLAPIVerifyTLS   bool          `koanf:"crowdsec_lapi_verify_tls"`
	CrowdSecLAPICACert      string        `koanf:"crowdsec_lapi_ca_cert"`
	CrowdSecLAPIAllowHTTP   bool          `koanf:"crowdsec_lapi_allow_http"`
	CrowdSecOrigins         []string      `koanf:"crowdsec_origins"`
	CrowdSecPollInterval    time.Duration `koanf:"crowdsec_poll_interval"`
	LAPIMetricsPushInterval time.Duration `koanf:"lapi_metrics_push_interval"`
	BlockScenarioExclude    []string      `koanf:"block_scenario_exclude"`
	BlockWhitelist          []string      `koanf:"block_whitelist"`
	BlockMinDuration        time.Duration `koanf:"block_min_duration"`
	// BlockScenarioDurationMap overrides the ban duration for specific scenarios.
	// Parsed from BLOCK_SCENARIO_DURATION_MAP=ssh-bf=168h,http-probing=24h
	BlockScenarioDurationMap map[string]time.Duration `koanf:"-"`

	// Decision Rate Limiting
	DecisionRateLimit int `koanf:"decision_rate_limit"` // decisions/second, 0 = unlimited
	DecisionBurstSize int `koanf:"decision_burst_size"`

	// Session Management
	SessionReauthMinGap  time.Duration `koanf:"session_reauth_min_gap"`
	SessionReauthTimeout time.Duration `koanf:"session_reauth_timeout"`

	// Storage
	DataDir string        `koanf:"data_dir"`
	BanTTL  time.Duration `koanf:"ban_ttl"`

	// Operational
	DryRun              bool          `koanf:"dry_run"`
	LogLevel            string        `koanf:"log_level"`
	LogFormat           string        `koanf:"log_format"`
	MetricsEnabled      bool          `koanf:"metrics_enabled"`
	MetricsAddr         string        `koanf:"metrics_addr"`
	HealthAddr          string        `koanf:"health_addr"`
	JanitorInterval     time.Duration `koanf:"janitor_interval"`
	ShutdownGracePeriod time.Duration `koanf:"shutdown_grace_period"`
	HealthCheckLAPI     bool          `koanf:"health_check_lapi"`

	// Storage
	HistoryMaxEvents int `koanf:"history_max_events"`

	// Blocklist import
	BlocklistURLs            []string      `koanf:"-"` // parsed from BLOCKLIST_URLS CSV
	BlocklistRefreshInterval time.Duration `koanf:"blocklist_refresh_interval"`

	// Webhook notifications
	WebhookURL    string   `koanf:"webhook_url"`
	WebhookEvents []string `koanf:"-"` // parsed from WEBHOOK_EVENTS CSV

	// DeprecationWarnings holds warnings about deprecated env vars that were
	// used. Callers should log these after building the logger.
	DeprecationWarnings []string `koanf:"-"`
}

// ZonePair represents a parsed src->dst zone pair, optionally with port and IP filters.
type ZonePair struct {
	Src      string
	Dst      string
	SrcPorts []int    // empty = any source ports
	DstPorts []int    // empty = any destination ports
	DstIPs   []string // empty = any destination IPs; CIDRs or plain IPs, IPv4 or IPv6
}

// parseZoneSide parses "zoneName[:port1,port2,...]" and returns the zone name
// and optional port list. A bare zone name (no colon) returns nil ports.
func parseZoneSide(side string) (zoneName string, ports []int, err error) {
	idx := strings.Index(side, ":")
	if idx == -1 {
		if side == "" {
			return "", nil, fmt.Errorf("zone name must not be empty")
		}
		if strings.Contains(side, ",") {
			return "", nil, fmt.Errorf("unexpected comma in zone name %q; separate pairs with semicolons when using port or destination IP lists", side)
		}
		return side, nil, nil
	}
	zoneName = side[:idx]
	if zoneName == "" {
		return "", nil, fmt.Errorf("zone name must not be empty")
	}
	portStr := side[idx+1:]
	if portStr == "" {
		return "", nil, fmt.Errorf("port list after ':' must not be empty")
	}
	portParts := strings.Split(portStr, ",")
	ports = make([]int, 0, len(portParts))
	for _, ps := range portParts {
		ps = strings.TrimSpace(ps)
		if ps == "" {
			return "", nil, fmt.Errorf("empty port in port list")
		}
		n, parseErr := strconv.Atoi(ps)
		if parseErr != nil {
			return "", nil, fmt.Errorf("invalid port %q: must be an integer", ps)
		}
		if n < 1 || n > 65535 {
			return "", nil, fmt.Errorf("port %d out of range (must be 1-65535)", n)
		}
		ports = append(ports, n)
	}
	return zoneName, ports, nil
}

// parseZonePairList parses zone pair strings in "src[:port,...]->dst[:port,...][@ip1,ip2,...]" format.
func parseZonePairList(pairs []string) ([]ZonePair, error) {
	result := make([]ZonePair, 0, len(pairs))
	for _, p := range pairs {
		if strings.Count(p, "->") != 1 {
			return nil, fmt.Errorf("invalid zone pair %q: expected one src->dst pair; separate pairs with semicolons when using comma-separated ports or destination IPs", p)
		}
		parts := strings.SplitN(p, "->", 2)
		src, srcPorts, err := parseZoneSide(strings.TrimSpace(parts[0]))
		if err != nil {
			return nil, fmt.Errorf("invalid zone pair %q src: %w", p, err)
		}

		// Split dst on '@' to extract optional destination IP list.
		dstRaw := strings.TrimSpace(parts[1])
		var dstIPs []string
		if idx := strings.Index(dstRaw, "@"); idx != -1 {
			ipPart := strings.TrimSpace(dstRaw[idx+1:])
			dstRaw = dstRaw[:idx]
			for _, ip := range strings.Split(ipPart, ",") {
				ip = strings.TrimSpace(ip)
				if ip == "" {
					return nil, fmt.Errorf("invalid zone pair %q: empty destination IP after @", p)
				}
				if strings.Contains(ip, "/") {
					if _, _, cidrErr := net.ParseCIDR(ip); cidrErr != nil {
						return nil, fmt.Errorf("invalid zone pair %q: invalid dst CIDR %q: %w", p, ip, cidrErr)
					}
				} else {
					if net.ParseIP(ip) == nil {
						return nil, fmt.Errorf("invalid zone pair %q: invalid dst IP %q", p, ip)
					}
				}
				dstIPs = append(dstIPs, ip)
			}
		}

		dst, dstPorts, err := parseZoneSide(dstRaw)
		if err != nil {
			return nil, fmt.Errorf("invalid zone pair %q dst: %w", p, err)
		}
		result = append(result, ZonePair{Src: src, Dst: dst, SrcPorts: srcPorts, DstPorts: dstPorts, DstIPs: dstIPs})
	}
	return result, nil
}

// ParseZonePairs parses ZONE_PAIRS in "src[:port,...]->dst[:port,...]" format.
func (c *Config) ParseZonePairs() ([]ZonePair, error) {
	return parseZonePairList(c.ZonePairs)
}

// ParseCloudflareZonePairs parses CLOUDFLARE_ZONE_PAIRS in "src[:port,...]->dst[:port,...]" format.
func (c *Config) ParseCloudflareZonePairs() ([]ZonePair, error) {
	return parseZonePairList(c.CloudflareZonePairs)
}

// ParseFirewallConnectionStates returns the zone block policy state filter.
// ALL preserves UniFi's unrestricted-state behavior for installations that
// intentionally want to block established and related traffic as well.
func (c *Config) ParseFirewallConnectionStates() ([]string, error) {
	raw := strings.TrimSpace(c.FirewallConnectionStates)
	if strings.EqualFold(raw, "ALL") {
		return nil, nil
	}
	if raw == "" {
		return nil, fmt.Errorf("FIREWALL_CONNECTION_STATES must be ALL or a comma-separated list of NEW,INVALID,ESTABLISHED")
	}
	allowed := map[string]bool{"NEW": true, "INVALID": true, "ESTABLISHED": true}
	seen := make(map[string]bool)
	var states []string
	for _, part := range strings.Split(raw, ",") {
		state := strings.ToUpper(strings.TrimSpace(part))
		if !allowed[state] || seen[state] {
			return nil, fmt.Errorf("FIREWALL_CONNECTION_STATES contains invalid or duplicate state %q", part)
		}
		seen[state] = true
		states = append(states, state)
	}
	return states, nil
}

// sanitise removes a single layer of matching surrounding quotes from all string
// fields and string slice elements. This normalises values from Docker --env-file
// which does not strip shell quoting.
func (c *Config) sanitise() {
	c.UnifiURL = stripEnvQuotes(c.UnifiURL)
	c.UnifiUsername = stripEnvQuotes(c.UnifiUsername)
	c.UnifiPassword = stripEnvQuotes(c.UnifiPassword)
	c.UnifiAPIKey = stripEnvQuotes(c.UnifiAPIKey)
	c.UnifiCACert = stripEnvQuotes(c.UnifiCACert)
	c.CrowdSecLAPIURL = stripEnvQuotes(c.CrowdSecLAPIURL)
	c.CrowdSecLAPICACert = stripEnvQuotes(c.CrowdSecLAPICACert)
	c.CrowdSecLAPIKey = stripEnvQuotes(c.CrowdSecLAPIKey)
	c.FirewallMode = stripEnvQuotes(c.FirewallMode)
	c.FirewallBlockAction = stripEnvQuotes(c.FirewallBlockAction)
	c.FirewallConnectionStates = stripEnvQuotes(c.FirewallConnectionStates)
	c.LegacyRulesetV4 = stripEnvQuotes(c.LegacyRulesetV4)
	c.LegacyRulesetV6 = stripEnvQuotes(c.LegacyRulesetV6)
	c.GroupNameTemplate = stripEnvQuotes(c.GroupNameTemplate)
	c.RuleNameTemplate = stripEnvQuotes(c.RuleNameTemplate)
	c.PolicyNameTemplate = stripEnvQuotes(c.PolicyNameTemplate)
	c.ObjectDescription = stripEnvQuotes(c.ObjectDescription)
	c.DataDir = stripEnvQuotes(c.DataDir)
	c.LogLevel = stripEnvQuotes(c.LogLevel)
	c.LogFormat = stripEnvQuotes(c.LogFormat)
	c.MetricsAddr = stripEnvQuotes(c.MetricsAddr)
	c.HealthAddr = stripEnvQuotes(c.HealthAddr)
	c.CloudflareIPv4URL = stripEnvQuotes(c.CloudflareIPv4URL)
	c.CloudflareIPv6URL = stripEnvQuotes(c.CloudflareIPv6URL)

	// Slice fields: strip each element
	for i, s := range c.UnifiSites {
		c.UnifiSites[i] = stripEnvQuotes(s)
	}
	for i, s := range c.CrowdSecOrigins {
		c.CrowdSecOrigins[i] = stripEnvQuotes(s)
	}
	for i, s := range c.BlockWhitelist {
		c.BlockWhitelist[i] = stripEnvQuotes(s)
	}
	for i, s := range c.BlockScenarioExclude {
		c.BlockScenarioExclude[i] = stripEnvQuotes(s)
	}
	for i, s := range c.ZonePairs {
		c.ZonePairs[i] = stripEnvQuotes(s)
	}
	for i, s := range c.CloudflareZonePairs {
		c.CloudflareZonePairs[i] = stripEnvQuotes(s)
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
		"enable_ipv6":                    false,
		"firewall_group_capacity":        10000,
		"firewall_api_shard_delay":       "250ms",
		"firewall_flush_concurrency":     1,
		"firewall_connection_states":     "NEW,INVALID",
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
		"lapi_metrics_push_interval":     "30m",
		"session_reauth_min_gap":         "5s",
		"session_reauth_timeout":         "10s",
		"data_dir":                       "/data",
		"ban_ttl":                        "168h",
		"log_level":                      "info",
		"log_format":                     "json",
		"metrics_enabled":                true,
		"metrics_addr":                   ":9090",
		"health_addr":                    ":8081",
		"janitor_interval":               "1h",
		"shutdown_grace_period":          "30s",
		"health_check_lapi":              true,
		"history_max_events":             10000,
		"blocklist_refresh_interval":     "24h",
		"decision_rate_limit":            0,
		"decision_burst_size":            1000,
		"unifi_require_https":            true,
		"unifi_sites_auto":               false,
	}
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

// Load reads configuration from environment variables, applying _FILE secret injection.
func Load() (*Config, error) {
	if _, misspelled := os.LookupEnv("CLOUDFLARE_ZWHITELIST_ENABLED"); misspelled {
		return nil, fmt.Errorf("unknown CLOUDFLARE_ZWHITELIST_ENABLED; use CLOUDFLARE_WHITELIST_ENABLED")
	}
	// Use "." as delimiter so that env vars with "_" in their names are
	// treated as flat keys, not nested paths. E.g. UNIFI_URL → "unifi_url"
	// maps to struct tag koanf:"unifi_url" without any nesting.
	k := koanf.New(".")

	// Apply defaults first
	defs := defaults()
	if err := k.Load(&rawProvider{data: defs}, nil); err != nil {
		return nil, fmt.Errorf("load defaults: %w", err)
	}

	// Load from environment — use "." as delimiter so env vars aren't split
	// by "_". Our env var names don't contain ".", so they stay flat.
	if err := k.Load(env.Provider("", ".", strings.ToLower), nil); err != nil {
		return nil, fmt.Errorf("load env: %w", err)
	}

	// Inject _FILE secrets
	if err := injectFileSecrets(k); err != nil {
		return nil, fmt.Errorf("inject file secrets: %w", err)
	}

	cfg := &Config{}
	if err := k.UnmarshalWithConf("", cfg, koanf.UnmarshalConf{Tag: "koanf"}); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	// Post-process comma-separated list fields that koanf won't split automatically
	cfg.UnifiSites = splitCSV(k.String("unifi_sites"))
	cfg.UnifiSitesExclude = splitCSV(k.String("unifi_sites_exclude"))
	cfg.CrowdSecOrigins = splitCSV(k.String("crowdsec_origins"))
	cfg.BlockScenarioExclude = splitCSV(k.String("block_scenario_exclude"))
	cfg.BlockWhitelist = splitCSV(k.String("block_whitelist"))
	cfg.ZonePairs = splitZonePairList(k.String("zone_pairs"))
	cfg.CloudflareZonePairs = splitZonePairList(k.String("cloudflare_zone_pairs"))
	cfg.BlocklistURLs = splitCSV(k.String("blocklist_urls"))
	cfg.WebhookEvents = splitCSV(k.String("webhook_events"))

	durationMap, err := parseScenarioDurationMap(k.String("block_scenario_duration_map"))
	if err != nil {
		return nil, fmt.Errorf("BLOCK_SCENARIO_DURATION_MAP: %w", err)
	}
	cfg.BlockScenarioDurationMap = durationMap

	if raw := strings.TrimSpace(k.String("zone_pairs_scenario_map")); raw != "" {
		return nil, fmt.Errorf("ZONE_PAIRS_SCENARIO_MAP is not supported: per-scenario firewall policies are not provisioned")
	}

	// Strip Docker env-file quoting from all string values
	cfg.sanitise()

	// Deprecation alias: FIREWALL_BATCH_WINDOW → SYNC_INTERVAL.
	// If the user set the old variable but not the new one, migrate the value.
	if bw := os.Getenv("FIREWALL_BATCH_WINDOW"); bw != "" && os.Getenv("SYNC_INTERVAL") == "" {
		if d, parseErr := time.ParseDuration(bw); parseErr == nil {
			cfg.SyncInterval = d
		}
		cfg.DeprecationWarnings = append(cfg.DeprecationWarnings,
			"FIREWALL_BATCH_WINDOW is deprecated; use SYNC_INTERVAL instead")
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate checks required fields and semantic constraints.
func (c *Config) Validate() error {
	if c.UnifiURL == "" {
		return fmt.Errorf("UNIFI_URL is required")
	}

	// Only HTTP(S) controller URLs are usable. An explicit opt-out is required
	// before credentials may be sent over plaintext HTTP.
	u, err := url.Parse(c.UnifiURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("UNIFI_URL must be an absolute http:// or https:// URL")
	}
	if u.Scheme == "http" {
		if c.UnifiRequireHTTPS {
			return fmt.Errorf("UNIFI_URL uses http:// — set UNIFI_REQUIRE_HTTPS=false to allow (not recommended)")
		}
		c.DeprecationWarnings = append(c.DeprecationWarnings,
			"UNIFI_URL uses http:// — credentials will be transmitted in plaintext; use https://")
	} else if !c.UnifiVerifyTLS {
		c.DeprecationWarnings = append(c.DeprecationWarnings,
			"UNIFI_VERIFY_TLS=false disables controller certificate validation; a network attacker could intercept credentials. Set UNIFI_VERIFY_TLS=true and configure UNIFI_CA_CERT for self-signed controllers")
	}
	if c.CrowdSecLAPIKey == "" {
		return fmt.Errorf("CROWDSEC_LAPI_KEY is required")
	}
	if c.UnifiAPIKey == "" && (c.UnifiUsername == "" || c.UnifiPassword == "") {
		return fmt.Errorf("either UNIFI_API_KEY or both UNIFI_USERNAME and UNIFI_PASSWORD are required")
	}

	validModes := map[string]bool{"auto": true, "legacy": true, "zone": true}
	if !validModes[c.FirewallMode] {
		return fmt.Errorf("FIREWALL_MODE must be auto, legacy, or zone; got %q", c.FirewallMode)
	}

	validActions := map[string]bool{"drop": true, "reject": true}
	if !validActions[c.FirewallBlockAction] {
		return fmt.Errorf("FIREWALL_BLOCK_ACTION must be drop or reject; got %q", c.FirewallBlockAction)
	}
	if _, err := c.ParseFirewallConnectionStates(); err != nil {
		return err
	}

	// Validate Go templates
	for _, pair := range []struct{ name, tmpl string }{
		{"GROUP_NAME_TEMPLATE", c.GroupNameTemplate},
		{"RULE_NAME_TEMPLATE", c.RuleNameTemplate},
		{"POLICY_NAME_TEMPLATE", c.PolicyNameTemplate},
	} {
		if _, err := template.New("").Parse(pair.tmpl); err != nil {
			return fmt.Errorf("%s is invalid Go template: %w", pair.name, err)
		}
	}

	// Validate zone pairs if mode is zone or auto
	if c.FirewallMode != "legacy" {
		if _, err := c.ParseZonePairs(); err != nil {
			return fmt.Errorf("ZONE_PAIRS: %w", err)
		}
	}

	validLogLevels := map[string]bool{
		"trace": true, "debug": true, "info": true,
		"warn": true, "error": true, "fatal": true, "panic": true,
	}
	if !validLogLevels[c.LogLevel] {
		return fmt.Errorf("LOG_LEVEL must be one of trace,debug,info,warn,error,fatal,panic; got %q", c.LogLevel)
	}

	if c.LogFormat != "json" && c.LogFormat != "text" {
		return fmt.Errorf("LOG_FORMAT must be json or text; got %q", c.LogFormat)
	}

	for _, entry := range c.BlockWhitelist {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			if _, _, err := net.ParseCIDR(entry); err != nil {
				return fmt.Errorf("BLOCK_WHITELIST: invalid CIDR %q: %w", entry, err)
			}
		} else {
			if net.ParseIP(entry) == nil {
				return fmt.Errorf("BLOCK_WHITELIST: invalid IP address %q", entry)
			}
		}
	}

	if !strings.HasPrefix(c.CrowdSecLAPIURL, "http://") && !strings.HasPrefix(c.CrowdSecLAPIURL, "https://") {
		return fmt.Errorf("CROWDSEC_LAPI_URL must start with http:// or https://; got %q", c.CrowdSecLAPIURL)
	}
	lapiURL, err := url.Parse(c.CrowdSecLAPIURL)
	if err != nil || lapiURL.Host == "" || lapiURL.User != nil {
		return fmt.Errorf("CROWDSEC_LAPI_URL must be an absolute URL without userinfo")
	}
	if lapiURL.Scheme == "http" && !isLoopbackHost(lapiURL.Hostname()) && !c.CrowdSecLAPIAllowHTTP {
		return fmt.Errorf("CROWDSEC_LAPI_URL uses plaintext HTTP outside loopback; set CROWDSEC_LAPI_ALLOW_HTTP=true only on a trusted local network")
	}
	if len(c.UnifiSites) == 0 && !c.UnifiSitesAuto {
		return fmt.Errorf("UNIFI_SITES must list at least one site, or set UNIFI_SITES_AUTO=true")
	}

	for _, capacity := range []struct {
		name  string
		value int
	}{
		{"FIREWALL_GROUP_CAPACITY", c.FirewallGroupCapacity},
		{"FIREWALL_GROUP_CAPACITY_V4", c.FirewallGroupCapacityV4},
		{"FIREWALL_GROUP_CAPACITY_V6", c.FirewallGroupCapacityV6},
	} {
		if capacity.value < 0 || capacity.value > 10000 {
			return fmt.Errorf("%s must be between 1 and 10000, or 0 to use the default (got %d)", capacity.name, capacity.value)
		}
	}

	if c.BanTTL <= 0 {
		return fmt.Errorf("BAN_TTL must be > 0; got %s", c.BanTTL)
	}

	if c.JanitorInterval <= 0 {
		return fmt.Errorf("JANITOR_INTERVAL must be > 0; got %s", c.JanitorInterval)
	}

	if c.SyncInterval < 5*time.Second {
		return fmt.Errorf("SYNC_INTERVAL must be at least 5s (got %s)", c.SyncInterval)
	}
	if c.ShardLimit < 1 || c.ShardLimit > 10000 {
		return fmt.Errorf("SHARD_LIMIT must be between 1 and 10000 (got %d)", c.ShardLimit)
	}
	if c.ShardMergeThreshold < -1 {
		return fmt.Errorf("SHARD_MERGE_THRESHOLD must be >= -1 (got %d); use -1 to disable rebalancing", c.ShardMergeThreshold)
	}
	if c.CrowdSecPollInterval <= 0 {
		return fmt.Errorf("CROWDSEC_POLL_INTERVAL must be > 0; got %s", c.CrowdSecPollInterval)
	}
	if c.ShutdownGracePeriod <= 0 {
		return fmt.Errorf("SHUTDOWN_GRACE_PERIOD must be > 0; got %s", c.ShutdownGracePeriod)
	}
	if c.FirewallFlushConcurrency < 1 {
		return fmt.Errorf("FIREWALL_FLUSH_CONCURRENCY must be >= 1; got %d", c.FirewallFlushConcurrency)
	}
	if c.DecisionRateLimit < 0 {
		return fmt.Errorf("DECISION_RATE_LIMIT must be >= 0; got %d", c.DecisionRateLimit)
	}
	// A zero burst makes every rate-limited wait fail immediately.
	if c.DecisionRateLimit > 0 && c.DecisionBurstSize < 1 {
		return fmt.Errorf("DECISION_BURST_SIZE must be >= 1 when DECISION_RATE_LIMIT is set; got %d", c.DecisionBurstSize)
	}
	if len(c.BlocklistURLs) > 0 && c.BlocklistRefreshInterval <= 0 {
		return fmt.Errorf("BLOCKLIST_REFRESH_INTERVAL must be > 0 when BLOCKLIST_URLS is set")
	}
	// Entries are named by position, never echoed: these URLs often carry tokens.
	for i, raw := range c.BlocklistURLs {
		if !isHTTPURL(raw) {
			return fmt.Errorf("BLOCKLIST_URLS entry %d must be an absolute http:// or https:// URL", i+1)
		}
	}
	if c.WebhookURL != "" && !isHTTPURL(c.WebhookURL) {
		return fmt.Errorf("WEBHOOK_URL must be an absolute http:// or https:// URL")
	}

	// Validate Cloudflare whitelist config
	if c.CloudflareWhitelistEnabled {
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
	}

	return nil
}

// InsecureLAPIURLWarning returns a non-empty warning message when the LAPI
// connection is susceptible to eavesdropping or a man-in-the-middle attack:
//   - http:// with a non-loopback host: LAPI key transmitted in plaintext.
//   - https:// with CROWDSEC_LAPI_VERIFY_TLS=false and a non-loopback host:
//     TLS is negotiated but certificate validation is disabled, so an attacker
//     on the network path can present a self-signed certificate and intercept
//     the LAPI key.
//
// Returns "" when the host is loopback/localhost (same machine), or when
// https:// is used with certificate verification enabled.
func (c *Config) InsecureLAPIURLWarning() string {
	u, err := url.Parse(c.CrowdSecLAPIURL)
	if err != nil {
		return ""
	}
	host := u.Hostname() // strips port and brackets from IPv6 literals
	if isLoopbackHost(host) {
		return ""
	}
	switch {
	case u.Scheme == "http":
		return "CROWDSEC_LAPI_URL uses http:// with a non-loopback host — " +
			"the LAPI key is transmitted in plaintext; use https:// in production"
	case u.Scheme == "https" && !c.CrowdSecLAPIVerifyTLS:
		return "CROWDSEC_LAPI_VERIFY_TLS is false with a non-loopback LAPI host — " +
			"TLS certificate validation is disabled and a man-in-the-middle attack could " +
			"intercept the LAPI key; set CROWDSEC_LAPI_VERIFY_TLS=true or mount a CA certificate"
	}
	return ""
}

// isLoopbackHost reports whether host is the loopback address or "localhost".
// isHTTPURL reports whether raw is an absolute http:// or https:// URL.
func isHTTPURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Host != "" && (u.Scheme == "http" || u.Scheme == "https")
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// injectFileSecrets reads _FILE env vars and injects their file contents.
var fileSecretKeys = []string{
	"unifi_username",
	"unifi_password",
	"unifi_api_key",
	"crowdsec_lapi_key",
}

func injectFileSecrets(k *koanf.Koanf) error {
	for _, key := range fileSecretKeys {
		fileKey := key + "_file"
		filePath := k.String(fileKey)
		if filePath == "" {
			// Also check uppercased env var with _FILE suffix
			envKey := strings.ToUpper(key) + "_FILE"
			filePath = os.Getenv(envKey)
		}
		if filePath == "" {
			continue
		}
		// Strip quotes from file path in case it was quoted in Docker --env-file
		filePath = stripEnvQuotes(filePath)
		content, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("reading secret file for %s (%s): %w", key, filePath, err)
		}
		val := strings.TrimSpace(string(content))
		if err := k.Set(key, val); err != nil {
			return fmt.Errorf("setting %s from file: %w", key, err)
		}
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

// splitZonePairList splits a zone-pair list string into individual zone pair
// strings. It handles two formats:
//
//  1. Semicolon-separated (required when any pair contains port lists):
//     "External:80,443->Internal;External->DMZ"
//
//  2. Comma-separated without port syntax (backward-compatible):
//     "wan->lan,wan->iot,wan->dmz"
//
// If the string contains semicolons, it is always split on semicolons.
// Otherwise, if every comma-separated part contains "->", the commas are
// treated as zone-pair separators (old-style format). If any part lacks "->",
// the entire string is treated as a single zone pair (commas are port
// separators within that pair, e.g. "External:80,443->Internal:80,443").
func splitZonePairList(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}

	// Prefer semicolons — unambiguous with port-list commas.
	if strings.Contains(s, ";") {
		parts := strings.Split(s, ";")
		result := make([]string, 0, len(parts))
		for _, p := range parts {
			// Keep empty entries so a stray separator is reported, not ignored.
			result = append(result, strings.TrimSpace(p))
		}
		return result
	}

	// Try comma split: only use it when every part contains "->" so we know
	// the commas are zone-pair separators, not port-list separators.
	parts := strings.Split(s, ",")
	allHaveArrow := true
	for _, p := range parts {
		if !strings.Contains(strings.TrimSpace(p), "->") {
			allHaveArrow = false
			break
		}
	}
	if allHaveArrow {
		result := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				result = append(result, p)
			}
		}
		return result
	}

	// Commas are port-list separators — the whole string is a single zone pair.
	return []string{s}
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

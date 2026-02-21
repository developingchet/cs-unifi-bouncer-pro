package config

import (
	"fmt"
	"net"
	"os"
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
	UnifiSites []string `koanf:"unifi_sites"`

	// Firewall Mode & Behavior
	FirewallMode              string        `koanf:"firewall_mode"`
	FirewallBlockAction       string        `koanf:"firewall_block_action"`
	FirewallEnableIPv6        bool          `koanf:"firewall_enable_ipv6"`
	FirewallGroupCapacity     int           `koanf:"firewall_group_capacity"`
	FirewallGroupCapacityV4   int           `koanf:"firewall_group_capacity_v4"`
	FirewallGroupCapacityV6   int           `koanf:"firewall_group_capacity_v6"`
	FirewallBatchWindow       time.Duration `koanf:"firewall_batch_window"`
	FirewallAPIShardDelay     time.Duration `koanf:"firewall_api_shard_delay"`
	FirewallFlushConcurrency  int           `koanf:"firewall_flush_concurrency"`
	FirewallLogDrops          bool          `koanf:"firewall_log_drops"`
	FirewallReconcileOnStart  bool          `koanf:"firewall_reconcile_on_start"`
	FirewallReconcileInterval time.Duration `koanf:"firewall_reconcile_interval"`

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
	ZonePairs            []string `koanf:"zone_pairs"`
	ZoneConnectionStates []string `koanf:"zone_connection_states"`
	ZonePolicyReorder    bool     `koanf:"zone_policy_reorder"`

	// CrowdSec Decision Filtering
	CrowdSecLAPIURL         string        `koanf:"crowdsec_lapi_url"`
	CrowdSecLAPIKey         string        `koanf:"crowdsec_lapi_key"`
	CrowdSecLAPIVerifyTLS   bool          `koanf:"crowdsec_lapi_verify_tls"`
	CrowdSecOrigins         []string      `koanf:"crowdsec_origins"`
	CrowdSecPollInterval    time.Duration `koanf:"crowdsec_poll_interval"`
	LAPIMetricsPushInterval time.Duration `koanf:"lapi_metrics_push_interval"`
	BlockScenarioExclude    []string      `koanf:"block_scenario_exclude"`
	BlockWhitelist          []string      `koanf:"block_whitelist"`
	BlockMinDuration        time.Duration `koanf:"block_min_duration"`

	// Worker Pool
	PoolWorkers    int           `koanf:"pool_workers"`
	PoolQueueDepth int           `koanf:"pool_queue_depth"`
	PoolMaxRetries int           `koanf:"pool_max_retries"`
	PoolRetryBase  time.Duration `koanf:"pool_retry_base"`

	// API Rate Gate
	RateLimitWindow   time.Duration `koanf:"ratelimit_window"`
	RateLimitMaxCalls int           `koanf:"ratelimit_max_calls"`

	// Session Management
	SessionReauthMinGap  time.Duration `koanf:"session_reauth_min_gap"`
	SessionReauthTimeout time.Duration `koanf:"session_reauth_timeout"`

	// Storage
	DataDir string        `koanf:"data_dir"`
	BanTTL  time.Duration `koanf:"ban_ttl"`

	// Operational
	DryRun          bool          `koanf:"dry_run"`
	LogLevel        string        `koanf:"log_level"`
	LogFormat       string        `koanf:"log_format"`
	MetricsEnabled  bool          `koanf:"metrics_enabled"`
	MetricsAddr     string        `koanf:"metrics_addr"`
	HealthAddr      string        `koanf:"health_addr"`
	JanitorInterval time.Duration `koanf:"janitor_interval"`
}

// ZonePair represents a parsed src->dst zone pair.
type ZonePair struct {
	Src string
	Dst string
}

// ParseZonePairs parses zone pair strings in "src->dst" format.
func (c *Config) ParseZonePairs() ([]ZonePair, error) {
	pairs := make([]ZonePair, 0, len(c.ZonePairs))
	for _, p := range c.ZonePairs {
		parts := strings.SplitN(p, "->", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid zone pair %q: expected format src->dst", p)
		}
		src := strings.TrimSpace(parts[0])
		dst := strings.TrimSpace(parts[1])
		if src == "" || dst == "" {
			return nil, fmt.Errorf("invalid zone pair %q: src and dst must not be empty", p)
		}
		pairs = append(pairs, ZonePair{Src: src, Dst: dst})
	}
	return pairs, nil
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
	c.CrowdSecLAPIKey = stripEnvQuotes(c.CrowdSecLAPIKey)
	c.FirewallMode = stripEnvQuotes(c.FirewallMode)
	c.FirewallBlockAction = stripEnvQuotes(c.FirewallBlockAction)
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
	for i, s := range c.ZoneConnectionStates {
		c.ZoneConnectionStates[i] = stripEnvQuotes(s)
	}
}

// defaults sets sensible default values.
func defaults() map[string]interface{} {
	return map[string]interface{}{
		"unifi_verify_tls":            false,
		"unifi_http_timeout":          "15s",
		"unifi_sites":                 "default",
		"firewall_mode":               "auto",
		"firewall_block_action":       "drop",
		"firewall_enable_ipv6":        true,
		"firewall_group_capacity":     10000,
		"firewall_batch_window":       "500ms",
		"firewall_api_shard_delay":    "250ms",
		"firewall_flush_concurrency":  1,
		"firewall_reconcile_on_start": true,
		"firewall_reconcile_interval": "0s",
		"group_name_template":         "crowdsec-block-{{.Family}}-{{.Index}}",
		"rule_name_template":          "crowdsec-drop-{{.Family}}-{{.Index}}",
		"policy_name_template":        "crowdsec-policy-{{.SrcZone}}-{{.DstZone}}-{{.Family}}-{{.Index}}",
		"object_description":          "Managed by cs-unifi-bouncer-pro. Do not edit manually.",
		"legacy_rule_index_start_v4":  22000,
		"legacy_rule_index_start_v6":  27000,
		"legacy_ruleset_v4":           "WAN_IN",
		"legacy_ruleset_v6":           "WANv6_IN",
		"zone_pairs":                  "External->Internal",
		"zone_connection_states":      "new,invalid",
		"zone_policy_reorder":         true,
		"crowdsec_lapi_url":           "http://crowdsec:8080",
		"crowdsec_lapi_verify_tls":    true,
		"crowdsec_poll_interval":      "30s",
		"lapi_metrics_push_interval":  "30m",
		"pool_workers":                4,
		"pool_queue_depth":            4096,
		"pool_max_retries":            3,
		"pool_retry_base":             "1s",
		"ratelimit_window":            "1m",
		"ratelimit_max_calls":         120,
		"session_reauth_min_gap":      "5s",
		"session_reauth_timeout":      "10s",
		"data_dir":                    "/data",
		"ban_ttl":                     "168h",
		"log_level":                   "info",
		"log_format":                  "json",
		"metrics_enabled":             true,
		"metrics_addr":                ":9090",
		"health_addr":                 ":8081",
		"janitor_interval":            "1h",
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
	if err := k.Load(env.Provider("", ".", func(s string) string {
		return strings.ToLower(s)
	}), nil); err != nil {
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
	cfg.CrowdSecOrigins = splitCSV(k.String("crowdsec_origins"))
	cfg.BlockScenarioExclude = splitCSV(k.String("block_scenario_exclude"))
	cfg.BlockWhitelist = splitCSV(k.String("block_whitelist"))
	cfg.ZonePairs = splitCSV(k.String("zone_pairs"))
	cfg.ZoneConnectionStates = splitCSV(k.String("zone_connection_states"))

	// Strip Docker env-file quoting from all string values
	cfg.sanitise()

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

	if c.PoolWorkers < 1 || c.PoolWorkers > 64 {
		return fmt.Errorf("POOL_WORKERS must be 1–64; got %d", c.PoolWorkers)
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

	if c.FirewallGroupCapacity != 0 && c.FirewallGroupCapacity < 1 {
		return fmt.Errorf("FIREWALL_GROUP_CAPACITY must be >= 1; got %d", c.FirewallGroupCapacity)
	}

	if c.PoolQueueDepth < 1 {
		return fmt.Errorf("POOL_QUEUE_DEPTH must be >= 1; got %d", c.PoolQueueDepth)
	}

	if c.BanTTL <= 0 {
		return fmt.Errorf("BAN_TTL must be > 0; got %s", c.BanTTL)
	}

	if c.JanitorInterval <= 0 {
		return fmt.Errorf("JANITOR_INTERVAL must be > 0; got %s", c.JanitorInterval)
	}

	return nil
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

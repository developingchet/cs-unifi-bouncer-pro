package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/v2"
)

// minResyncInterval keeps the full decision re-read from hammering the LAPI:
// with a large community blocklist one pull is tens of megabytes.
const minResyncInterval = 5 * time.Minute

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
	UnifiSitesExclude []string `koanf:"-" setting:"UNIFI_SITES_EXCLUDE"`

	// UniFi Security
	UnifiRequireHTTPS bool `koanf:"unifi_require_https"`

	// Firewall Mode & Behavior
	FirewallMode              string        `koanf:"firewall_mode"`
	FirewallBlockAction       string        `koanf:"firewall_block_action"`
	FirewallEnableIPv6        bool          `koanf:"firewall_enable_ipv6"`
	UnifiDialIPv6             bool          `koanf:"unifi_dial_ipv6"`         // controller client IPv6 dialing; ENABLE_IPV6 is the deprecated name
	FirewallGroupCapacity     int           `koanf:"firewall_group_capacity"` // deprecated shard limit names; see ShardCapacities
	FirewallGroupCapacityV4   int           `koanf:"firewall_group_capacity_v4"`
	FirewallGroupCapacityV6   int           `koanf:"firewall_group_capacity_v6"`
	FirewallAPIShardDelay     time.Duration `koanf:"firewall_api_shard_delay"`
	FirewallLogDrops          bool          `koanf:"firewall_log_drops"`
	FirewallConnectionStates  string        `koanf:"firewall_connection_states"`
	FirewallReconcileOnStart  bool          `koanf:"firewall_reconcile_on_start"`
	FirewallReconcileInterval time.Duration `koanf:"firewall_reconcile_interval"`

	// Shard Management (integration v1)
	SyncInterval time.Duration `koanf:"sync_interval"`
	ShardLimit   int           `koanf:"shard_limit"`
	// ShardLimitV4 and ShardLimitV6 lower ShardLimit for one address family;
	// 0 uses ShardLimit.
	ShardLimitV4 int `koanf:"shard_limit_v4"`
	ShardLimitV6 int `koanf:"shard_limit_v6"`
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
	// EgressZonePairs are zone pairs whose block policies match banned
	// addresses as the destination, stopping hosts in the source zone from
	// connecting out to them.
	EgressZonePairs        []string `koanf:"egress_zone_pairs"`
	EgressConnectionStates string   `koanf:"egress_connection_states"`

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
	CrowdSecLAPIURL       string        `koanf:"crowdsec_lapi_url"`
	CrowdSecLAPIKey       string        `koanf:"crowdsec_lapi_key"`
	CrowdSecLAPIVerifyTLS bool          `koanf:"crowdsec_lapi_verify_tls"`
	CrowdSecLAPICACert    string        `koanf:"crowdsec_lapi_ca_cert"`
	CrowdSecLAPIAllowHTTP bool          `koanf:"crowdsec_lapi_allow_http"`
	CrowdSecOrigins       []string      `koanf:"crowdsec_origins"`
	CrowdSecPollInterval  time.Duration `koanf:"crowdsec_poll_interval"`
	// CrowdSecResyncInterval is how often every active decision is re-read
	// from the LAPI to recover bans the stream skipped; 0 disables it.
	CrowdSecResyncInterval  time.Duration `koanf:"crowdsec_resync_interval"`
	LAPIMetricsPushInterval time.Duration `koanf:"lapi_metrics_push_interval"`
	BlockScenarioExclude    []string      `koanf:"block_scenario_exclude"`
	BlockDecisionTypes      []string      `koanf:"-" setting:"BLOCK_DECISION_TYPES"`
	BlockWhitelist          []string      `koanf:"block_whitelist"`
	BlockMinDuration        time.Duration `koanf:"block_min_duration"`
	// BlockScenarioDurationMap overrides the ban duration for specific scenarios.
	// Parsed from BLOCK_SCENARIO_DURATION_MAP=ssh-bf=168h,http-probing=24h
	BlockScenarioDurationMap map[string]time.Duration `koanf:"-" setting:"BLOCK_SCENARIO_DURATION_MAP"`

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
	BlocklistURLs            []string      `koanf:"-" setting:"BLOCKLIST_URLS"`
	BlocklistRefreshInterval time.Duration `koanf:"blocklist_refresh_interval"`
	// BlocklistMinPrefixV4 and V6 are the shortest prefix lengths a feed
	// entry may have. Shorter ranges are skipped like any other unbannable
	// entry. They apply to BLOCKLIST_URLS and the AbuseIPDB feed, not to
	// CrowdSec decisions.
	BlocklistMinPrefixV4 int `koanf:"blocklist_min_prefix_v4"`
	BlocklistMinPrefixV6 int `koanf:"blocklist_min_prefix_v6"`

	// AbuseIPDB feed (github.com/borestad/blocklist-abuseipdb)
	AbuseIPDBList            string        `koanf:"abuseipdb_list"`
	AbuseIPDBURLOverride     string        `koanf:"abuseipdb_url"`
	AbuseIPDBCountryInclude  []string      `koanf:"-" setting:"ABUSEIPDB_COUNTRY_INCLUDE"`
	AbuseIPDBCountryExclude  []string      `koanf:"-" setting:"ABUSEIPDB_COUNTRY_EXCLUDE"`
	AbuseIPDBRefreshInterval time.Duration `koanf:"abuseipdb_refresh_interval"`

	// Webhook notifications
	WebhookURL    string   `koanf:"webhook_url"`
	WebhookEvents []string `koanf:"-" setting:"WEBHOOK_EVENTS"`

	// DeprecationWarnings holds warnings about deprecated env vars that were
	// used. Callers should log these after building the logger.
	DeprecationWarnings []string `koanf:"-"`
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

	if err := injectFileSettings(k); err != nil {
		return nil, fmt.Errorf("read _FILE settings: %w", err)
	}
	if err := unquoteValues(k); err != nil {
		return nil, err
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
	cfg.BlockDecisionTypes = parseBlockDecisionTypes(k.String("block_decision_types"))
	cfg.BlockWhitelist = splitCSV(k.String("block_whitelist"))
	cfg.ZonePairs = splitZonePairList(k.String("zone_pairs"))
	cfg.CloudflareZonePairs = splitZonePairList(k.String("cloudflare_zone_pairs"))
	cfg.EgressZonePairs = splitZonePairList(k.String("egress_zone_pairs"))
	cfg.BlocklistURLs = splitCSV(k.String("blocklist_urls"))
	cfg.AbuseIPDBCountryInclude = splitCountryCodes(k.String("abuseipdb_country_include"))
	cfg.AbuseIPDBCountryExclude = splitCountryCodes(k.String("abuseipdb_country_exclude"))
	cfg.WebhookEvents = splitCSV(k.String("webhook_events"))

	durationMap, err := parseScenarioDurationMap(k.String("block_scenario_duration_map"))
	if err != nil {
		return nil, fmt.Errorf("BLOCK_SCENARIO_DURATION_MAP: %w", err)
	}
	cfg.BlockScenarioDurationMap = durationMap

	if raw := strings.TrimSpace(k.String("zone_pairs_scenario_map")); raw != "" {
		return nil, fmt.Errorf("ZONE_PAIRS_SCENARIO_MAP is not supported: per-scenario firewall policies are not provisioned")
	}

	cfg.sanitise()
	cfg.applySettingAliases(k)

	// Deprecation alias: FIREWALL_BATCH_WINDOW → SYNC_INTERVAL.
	// If the user set the old variable but not the new one, migrate the value.
	// SYNC_INTERVAL is looked up in the environment: koanf holds its default.
	if bw := strings.TrimSpace(k.String("firewall_batch_window")); bw != "" && strings.TrimSpace(os.Getenv("SYNC_INTERVAL")) == "" {
		d, parseErr := time.ParseDuration(bw)
		if parseErr != nil {
			return nil, fmt.Errorf("FIREWALL_BATCH_WINDOW (deprecated; use SYNC_INTERVAL) must be a duration such as 30s; got %q", bw)
		}
		cfg.SyncInterval = d
		cfg.DeprecationWarnings = append(cfg.DeprecationWarnings,
			"FIREWALL_BATCH_WINDOW is deprecated; use SYNC_INTERVAL instead")
	}
	if os.Getenv("FIREWALL_FLUSH_CONCURRENCY") != "" {
		cfg.DeprecationWarnings = append(cfg.DeprecationWarnings,
			"FIREWALL_FLUSH_CONCURRENCY has no effect: shards are written one at a time; remove it")
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

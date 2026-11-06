package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// Validate checks required fields and semantic constraints.
func (c *Config) Validate() error {
	if err := c.validateController(); err != nil {
		return err
	}
	if err := c.validateFirewall(); err != nil {
		return err
	}
	if err := c.validateOperational(); err != nil {
		return err
	}
	if err := c.validateTiming(); err != nil {
		return err
	}
	if err := c.validateShardLimits(); err != nil {
		return err
	}
	if err := c.validateBlockDecisionTypes(); err != nil {
		return err
	}
	if err := c.validateFeeds(); err != nil {
		return err
	}
	if err := c.validateCloudflare(); err != nil {
		return err
	}
	return c.validatePairSites()
}

// validateController checks the UniFi controller URL/TLS settings and the
// required UniFi and CrowdSec credentials.
func (c *Config) validateController() error {
	if c.UnifiURL == "" {
		return fmt.Errorf("UNIFI_URL is required")
	}

	// Only HTTP(S) controller URLs are usable. An explicit opt-out is required
	// before credentials may be sent over plaintext HTTP.
	u, err := url.Parse(c.UnifiURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("UNIFI_URL must be an absolute http:// or https:// URL")
	}
	// Credentials belong in UNIFI_USERNAME/UNIFI_PASSWORD: a URL is printed
	// by diagnose and by UNIFI_API_DEBUG request logs.
	if u.User != nil {
		return fmt.Errorf("UNIFI_URL must not contain a username or password; use UNIFI_USERNAME and UNIFI_PASSWORD")
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
	return nil
}

// validateOperational checks logging, the block whitelist, the CrowdSec LAPI
// URL, the configured UniFi sites, and firewall group capacity.
func (c *Config) validateOperational() error {
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
	if c.HealthAddr == "" {
		return fmt.Errorf("HEALTH_ADDR must not be empty; the healthcheck subcommand probes %s when it is unset", defaultHealthAddr)
	}
	if c.MetricsEnabled && c.MetricsAddr == c.HealthAddr {
		return fmt.Errorf("METRICS_ADDR and HEALTH_ADDR must differ; both are %q", c.MetricsAddr)
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
	return nil
}

// validateTiming checks the ban/sync/reconcile durations and decision rate
// limiting settings.
func (c *Config) validateTiming() error {
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
	if c.CrowdSecResyncInterval != 0 && c.CrowdSecResyncInterval < minResyncInterval {
		return fmt.Errorf("CROWDSEC_RESYNC_INTERVAL must be 0 (disabled) or at least %s; got %s",
			minResyncInterval, c.CrowdSecResyncInterval)
	}
	if c.ShutdownGracePeriod <= 0 {
		return fmt.Errorf("SHUTDOWN_GRACE_PERIOD must be > 0; got %s", c.ShutdownGracePeriod)
	}
	// A zero client timeout means no timeout, so a stalled controller would
	// hang every sync.
	if c.UnifiHTTPTimeout <= 0 {
		return fmt.Errorf("UNIFI_HTTP_TIMEOUT must be > 0; got %s", c.UnifiHTTPTimeout)
	}
	if c.SessionReauthTimeout <= 0 {
		return fmt.Errorf("SESSION_REAUTH_TIMEOUT must be > 0; got %s", c.SessionReauthTimeout)
	}
	if c.CircuitBreakerThreshold < 1 {
		return fmt.Errorf("CIRCUIT_BREAKER_THRESHOLD must be >= 1; got %d", c.CircuitBreakerThreshold)
	}
	if c.CircuitBreakerResetInterval <= 0 {
		return fmt.Errorf("CIRCUIT_BREAKER_RESET_INTERVAL must be > 0; got %s", c.CircuitBreakerResetInterval)
	}
	for _, d := range []struct {
		name  string
		value time.Duration
	}{
		{"FIREWALL_API_SHARD_DELAY", c.FirewallAPIShardDelay},
		{"FIREWALL_RECONCILE_INTERVAL", c.FirewallReconcileInterval},
		{"SESSION_REAUTH_MIN_GAP", c.SessionReauthMinGap},
	} {
		if d.value < 0 {
			return fmt.Errorf("%s must not be negative; got %s", d.name, d.value)
		}
	}
	if c.DecisionRateLimit < 0 {
		return fmt.Errorf("DECISION_RATE_LIMIT must be >= 0; got %d", c.DecisionRateLimit)
	}
	// A zero burst makes every rate-limited wait fail immediately.
	if c.DecisionRateLimit > 0 && c.DecisionBurstSize < 1 {
		return fmt.Errorf("DECISION_BURST_SIZE must be >= 1 when DECISION_RATE_LIMIT is set; got %d", c.DecisionBurstSize)
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

// isHTTPURL reports whether raw is an absolute http:// or https:// URL.
func isHTTPURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Host != "" && (u.Scheme == "http" || u.Scheme == "https")
}

func isHTTPSURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Host != "" && u.Scheme == "https"
}

// isLoopbackHost reports whether host is the loopback address or "localhost".
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

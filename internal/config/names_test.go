package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoadRejectsLegacyGroupNamesOver64Characters(t *testing.T) {
	long := strings.Repeat("x", 58) + "-{{.Family}}-{{.Index}}" // 58 + "-v4-0" = 63
	tests := []struct {
		name    string
		env     map[string]string
		wantErr string
	}{
		{name: "63 characters", env: map[string]string{"GROUP_NAME_TEMPLATE": long}},
		{
			name:    "65 characters",
			env:     map[string]string{"GROUP_NAME_TEMPLATE": "xx" + long},
			wantErr: `(65 characters) for site "default"; legacy firewall groups are limited to 64 characters`,
		},
		{
			name: "too long with a configured site",
			env: map[string]string{
				"UNIFI_SITES":         "default,branch-office-east",
				"GROUP_NAME_TEMPLATE": "crowdsec-block-" + strings.Repeat("y", 30) + "-{{.Site}}-{{.Family}}-{{.Index}}",
			},
			wantErr: `for site "branch-office-east"; legacy firewall groups are limited to 64 characters`,
		},
		{
			name: "zone mode has no limit",
			env:  map[string]string{"FIREWALL_MODE": "zone", "GROUP_NAME_TEMPLATE": "xx" + long},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadWith(t, tc.env)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Load: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) || !strings.HasPrefix(err.Error(), "GROUP_NAME_TEMPLATE renders ") {
				t.Fatalf("Load = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestValidateRejectsUnusableSettings(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*Config)
		wantErr string
	}{
		{"template field that does not exist", func(c *Config) { c.GroupNameTemplate = "block-{{.Foo}}-{{.Index}}" }, "GROUP_NAME_TEMPLATE cannot be rendered"},
		{"template without the shard index", func(c *Config) { c.RuleNameTemplate = "drop-{{.Family}}" }, "RULE_NAME_TEMPLATE must include {{.Index}}"},
		{"template that renders nothing", func(c *Config) { c.PolicyNameTemplate = "{{if false}}{{.Index}}{{end}}" }, "POLICY_NAME_TEMPLATE renders an empty name"},
		{"controller URL with credentials", func(c *Config) { c.UnifiURL = "https://admin:secret@192.168.1.1" }, "UNIFI_URL must not contain a username or password"},
		{"unknown webhook event", func(c *Config) { c.WebhookEvents = []string{"circuit_breaker_open", "breaker_open"} }, `WEBHOOK_EVENTS: unknown event "breaker_open"`},
		{"no controller timeout", func(c *Config) { c.UnifiHTTPTimeout = 0 }, "UNIFI_HTTP_TIMEOUT must be > 0"},
		{"no re-auth timeout", func(c *Config) { c.SessionReauthTimeout = 0 }, "SESSION_REAUTH_TIMEOUT must be > 0"},
		{"breaker threshold 0", func(c *Config) { c.CircuitBreakerThreshold = 0 }, "CIRCUIT_BREAKER_THRESHOLD must be >= 1"},
		{"breaker reset 0", func(c *Config) { c.CircuitBreakerResetInterval = 0 }, "CIRCUIT_BREAKER_RESET_INTERVAL must be > 0"},
		{"negative shard delay", func(c *Config) { c.FirewallAPIShardDelay = -time.Second }, "FIREWALL_API_SHARD_DELAY must not be negative"},
		{"negative reconcile interval", func(c *Config) { c.FirewallReconcileInterval = -time.Second }, "FIREWALL_RECONCILE_INTERVAL must not be negative"},
		{"negative re-auth gap", func(c *Config) { c.SessionReauthMinGap = -time.Second }, "SESSION_REAUTH_MIN_GAP must not be negative"},
		{"metrics and health on one port", func(c *Config) { c.MetricsAddr = ":8081" }, `METRICS_ADDR and HEALTH_ADDR must differ`},
		{"empty health address", func(c *Config) { c.HealthAddr = "" }, "HEALTH_ADDR must not be empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setEnv(t, "UNIFI_URL", "https://192.168.1.1")
			setEnv(t, "UNIFI_API_KEY", "my-api-key")
			setEnv(t, "CROWDSEC_LAPI_KEY", "lapi-key")
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			tt.modify(cfg)
			err = cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() = %v, want an error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateAcceptsCustomTemplatesAndEvents(t *testing.T) {
	setEnv(t, "UNIFI_URL", "https://192.168.1.1")
	setEnv(t, "UNIFI_API_KEY", "my-api-key")
	setEnv(t, "CROWDSEC_LAPI_KEY", "lapi-key")
	setEnv(t, "GROUP_NAME_TEMPLATE", "cs-{{.Site}}-{{.Family}}-{{.Index}}")
	setEnv(t, "WEBHOOK_URL", "https://hooks.example/x")
	setEnv(t, "WEBHOOK_EVENTS", "circuit_breaker_open,reconcile_drift")
	if _, err := Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
}

func TestHealthAddrFromEnv(t *testing.T) {
	tests := []struct{ name, env, want string }{
		{"unset", "", ":8081"},
		{"set", "127.0.0.1:9000", "127.0.0.1:9000"},
		{"quoted by --env-file", `":8181"`, ":8181"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setEnv(t, "HEALTH_ADDR", tt.env)
			if got := HealthAddrFromEnv(); got != tt.want {
				t.Fatalf("HealthAddrFromEnv() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFlushConcurrencyIsReportedAsIgnored(t *testing.T) {
	setEnv(t, "UNIFI_URL", "https://192.168.1.1")
	setEnv(t, "UNIFI_API_KEY", "my-api-key")
	setEnv(t, "CROWDSEC_LAPI_KEY", "lapi-key")
	setEnv(t, "FIREWALL_FLUSH_CONCURRENCY", "4")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, w := range cfg.DeprecationWarnings {
		if strings.Contains(w, "FIREWALL_FLUSH_CONCURRENCY has no effect") {
			return
		}
	}
	t.Fatalf("no warning in %v", cfg.DeprecationWarnings)
}

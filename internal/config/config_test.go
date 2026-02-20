package config

import (
	"os"
	"path/filepath"
	"testing"
)

func setEnv(t *testing.T, key, val string) {
	t.Helper()
	t.Setenv(key, val)
}

func TestLoadMissingRequired(t *testing.T) {
	// Clear any env vars that might be set
	os.Unsetenv("UNIFI_URL")
	os.Unsetenv("CROWDSEC_LAPI_KEY")
	os.Unsetenv("UNIFI_API_KEY")
	os.Unsetenv("UNIFI_USERNAME")
	os.Unsetenv("UNIFI_PASSWORD")

	_, err := Load()
	if err == nil {
		t.Error("expected error when UNIFI_URL missing")
	}
}

func TestLoadMinimalValid(t *testing.T) {
	setEnv(t, "UNIFI_URL", "https://192.168.1.1")
	setEnv(t, "UNIFI_API_KEY", "my-api-key")
	setEnv(t, "CROWDSEC_LAPI_KEY", "lapi-key")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.UnifiURL != "https://192.168.1.1" {
		t.Errorf("UnifiURL: got %q", cfg.UnifiURL)
	}
	if cfg.UnifiAPIKey != "my-api-key" {
		t.Errorf("UnifiAPIKey: got %q", cfg.UnifiAPIKey)
	}
}

func TestFileSecretInjection(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "api_key.txt")
	if err := os.WriteFile(keyFile, []byte("  secret-from-file  \n"), 0600); err != nil {
		t.Fatal(err)
	}

	setEnv(t, "UNIFI_URL", "https://192.168.1.1")
	setEnv(t, "UNIFI_API_KEY_FILE", keyFile)
	setEnv(t, "CROWDSEC_LAPI_KEY", "lapi-key")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load with file secret: %v", err)
	}
	if cfg.UnifiAPIKey != "secret-from-file" {
		t.Errorf("expected trimmed file secret, got %q", cfg.UnifiAPIKey)
	}
}

func TestZonePairsParsing(t *testing.T) {
	setEnv(t, "UNIFI_URL", "https://192.168.1.1")
	setEnv(t, "UNIFI_API_KEY", "key")
	setEnv(t, "CROWDSEC_LAPI_KEY", "lapi-key")
	setEnv(t, "ZONE_PAIRS", "wan->lan,wan->iot,wan->dmz")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	pairs, err := cfg.ParseZonePairs()
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 3 {
		t.Errorf("expected 3 zone pairs, got %d", len(pairs))
	}
	if pairs[0].Src != "wan" || pairs[0].Dst != "lan" {
		t.Errorf("first pair: got %+v", pairs[0])
	}
	if pairs[2].Dst != "dmz" {
		t.Errorf("third pair dst: got %q", pairs[2].Dst)
	}
}

func TestInvalidZonePairs(t *testing.T) {
	setEnv(t, "UNIFI_URL", "https://192.168.1.1")
	setEnv(t, "UNIFI_API_KEY", "key")
	setEnv(t, "CROWDSEC_LAPI_KEY", "lapi-key")
	setEnv(t, "ZONE_PAIRS", "invalid-format")
	setEnv(t, "FIREWALL_MODE", "zone")

	_, err := Load()
	if err == nil {
		t.Error("expected error for invalid zone pair format")
	}
}

func TestInvalidFirewallMode(t *testing.T) {
	setEnv(t, "UNIFI_URL", "https://192.168.1.1")
	setEnv(t, "UNIFI_API_KEY", "key")
	setEnv(t, "CROWDSEC_LAPI_KEY", "lapi-key")
	setEnv(t, "FIREWALL_MODE", "invalid")

	_, err := Load()
	if err == nil {
		t.Error("expected error for invalid FIREWALL_MODE")
	}
}

func TestInvalidPoolWorkers(t *testing.T) {
	setEnv(t, "UNIFI_URL", "https://192.168.1.1")
	setEnv(t, "UNIFI_API_KEY", "key")
	setEnv(t, "CROWDSEC_LAPI_KEY", "lapi-key")
	setEnv(t, "POOL_WORKERS", "100") // > 64

	_, err := Load()
	if err == nil {
		t.Error("expected error for invalid POOL_WORKERS")
	}
}

func TestInvalidTemplateValidation(t *testing.T) {
	setEnv(t, "UNIFI_URL", "https://192.168.1.1")
	setEnv(t, "UNIFI_API_KEY", "key")
	setEnv(t, "CROWDSEC_LAPI_KEY", "lapi-key")
	setEnv(t, "GROUP_NAME_TEMPLATE", "{{.Invalid unclosed")

	_, err := Load()
	if err == nil {
		t.Error("expected error for invalid Go template")
	}
}

func TestDefaults(t *testing.T) {
	setEnv(t, "UNIFI_URL", "https://192.168.1.1")
	setEnv(t, "UNIFI_API_KEY", "key")
	setEnv(t, "CROWDSEC_LAPI_KEY", "lapi-key")
	// Clear any previously set env vars that override defaults
	os.Unsetenv("FIREWALL_MODE")
	os.Unsetenv("POOL_WORKERS")
	os.Unsetenv("ZONE_PAIRS")
	os.Unsetenv("GROUP_NAME_TEMPLATE")
	os.Unsetenv("POOL_WORKERS")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.FirewallMode != "auto" {
		t.Errorf("default FirewallMode: got %q", cfg.FirewallMode)
	}
	if cfg.PoolWorkers != 4 {
		t.Errorf("default PoolWorkers: got %d", cfg.PoolWorkers)
	}
	if cfg.GroupNameTemplate != "crowdsec-block-{{.Family}}-{{.Index}}" {
		t.Errorf("default GroupNameTemplate: got %q", cfg.GroupNameTemplate)
	}
	if len(cfg.ZonePairs) != 1 || cfg.ZonePairs[0] != "External->Internal" {
		t.Errorf("default ZonePairs: got %v", cfg.ZonePairs)
	}
	if !cfg.ZonePolicyReorder {
		t.Errorf("default ZonePolicyReorder: expected true, got false")
	}
}

func TestMultiSiteConfig(t *testing.T) {
	setEnv(t, "UNIFI_URL", "https://192.168.1.1")
	setEnv(t, "UNIFI_API_KEY", "key")
	setEnv(t, "CROWDSEC_LAPI_KEY", "lapi-key")
	setEnv(t, "UNIFI_SITES", "default,homelab,iot")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.UnifiSites) != 3 {
		t.Errorf("expected 3 sites, got %d", len(cfg.UnifiSites))
	}
	if cfg.UnifiSites[1] != "homelab" {
		t.Errorf("second site: got %q", cfg.UnifiSites[1])
	}
}

// baseEnv sets the minimum required fields for a valid config and clears
// fields that might cause spurious validation failures between test cases.
func baseEnv(t *testing.T) {
	t.Helper()
	setEnv(t, "UNIFI_URL", "https://192.168.1.1")
	setEnv(t, "UNIFI_API_KEY", "key")
	setEnv(t, "CROWDSEC_LAPI_KEY", "lapi-key")
	// Reset fields that the new validation touches to their valid defaults
	os.Unsetenv("LOG_LEVEL")
	os.Unsetenv("LOG_FORMAT")
	os.Unsetenv("BLOCK_WHITELIST")
	os.Unsetenv("CROWDSEC_LAPI_URL")
	os.Unsetenv("FIREWALL_GROUP_CAPACITY")
	os.Unsetenv("POOL_QUEUE_DEPTH")
	os.Unsetenv("BAN_TTL")
	os.Unsetenv("JANITOR_INTERVAL")
	os.Unsetenv("FIREWALL_MODE")
	os.Unsetenv("ZONE_PAIRS")
}

func TestValidation(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(t *testing.T)
		wantErr bool
	}{
		{
			name: "valid_minimal",
			setup: func(t *testing.T) {
				// baseEnv already set in each test iteration
			},
			wantErr: false,
		},
		{
			name: "invalid_log_level",
			setup: func(t *testing.T) {
				setEnv(t, "LOG_LEVEL", "invalid")
			},
			wantErr: true,
		},
		{
			name: "valid_log_level_debug",
			setup: func(t *testing.T) {
				setEnv(t, "LOG_LEVEL", "debug")
			},
			wantErr: false,
		},
		{
			name: "invalid_log_format",
			setup: func(t *testing.T) {
				setEnv(t, "LOG_FORMAT", "yaml")
			},
			wantErr: true,
		},
		{
			name: "valid_log_format_text",
			setup: func(t *testing.T) {
				setEnv(t, "LOG_FORMAT", "text")
			},
			wantErr: false,
		},
		{
			name: "invalid_block_whitelist_not_ip",
			setup: func(t *testing.T) {
				setEnv(t, "BLOCK_WHITELIST", "not-an-ip")
			},
			wantErr: true,
		},
		{
			name: "valid_block_whitelist_cidr",
			setup: func(t *testing.T) {
				setEnv(t, "BLOCK_WHITELIST", "192.168.0.0/16")
			},
			wantErr: false,
		},
		{
			name: "invalid_crowdsec_lapi_url_ftp",
			setup: func(t *testing.T) {
				setEnv(t, "CROWDSEC_LAPI_URL", "ftp://host")
			},
			wantErr: true,
		},
		{
			name: "valid_crowdsec_lapi_url_https",
			setup: func(t *testing.T) {
				setEnv(t, "CROWDSEC_LAPI_URL", "https://crowdsec:8080")
			},
			wantErr: false,
		},
		{
			name: "firewall_group_capacity_zero_valid",
			setup: func(t *testing.T) {
				setEnv(t, "FIREWALL_GROUP_CAPACITY", "0")
			},
			wantErr: false, // 0 means "use default"
		},
		{
			name: "invalid_janitor_interval_zero",
			setup: func(t *testing.T) {
				setEnv(t, "JANITOR_INTERVAL", "0s")
			},
			wantErr: true,
		},
		{
			name: "invalid_ban_ttl_zero",
			setup: func(t *testing.T) {
				setEnv(t, "BAN_TTL", "0s")
			},
			wantErr: true,
		},
		{
			name: "invalid_pool_queue_depth_zero",
			setup: func(t *testing.T) {
				setEnv(t, "POOL_QUEUE_DEPTH", "0")
			},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			baseEnv(t)
			tc.setup(t)

			_, err := Load()
			if tc.wantErr && err == nil {
				t.Errorf("expected validation error, got nil")
			} else if !tc.wantErr && err != nil {
				t.Errorf("expected no error, got: %v", err)
			}
		})
	}
}

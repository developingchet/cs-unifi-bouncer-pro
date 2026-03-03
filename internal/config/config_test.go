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

func TestStripEnvQuotes(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"'https://example.com'", "https://example.com"},
		{`"https://example.com"`, "https://example.com"},
		{"https://example.com", "https://example.com"}, // no quotes — unchanged
		{"'mismatched\"", "'mismatched\""},             // unpaired — unchanged
		{"''", ""},                                     // empty quoted string
		{"'", "'"},                                     // single char — unchanged
		{"", ""},                                       // empty — unchanged
		{"'nested 'quotes''", "nested 'quotes'"},       // only outer pair stripped
	}
	for _, tc := range cases {
		if got := stripEnvQuotes(tc.in); got != tc.want {
			t.Errorf("stripEnvQuotes(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
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

func TestParseZonePairs_NoPort(t *testing.T) {
	cfg := &Config{ZonePairs: []string{"External->Internal"}}
	pairs, err := cfg.ParseZonePairs()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pairs) != 1 {
		t.Fatalf("expected 1 pair, got %d", len(pairs))
	}
	if pairs[0].Src != "External" || pairs[0].Dst != "Internal" {
		t.Errorf("unexpected pair: %+v", pairs[0])
	}
	if len(pairs[0].SrcPorts) != 0 || len(pairs[0].DstPorts) != 0 {
		t.Errorf("expected empty ports for no-port pair, got src=%v dst=%v", pairs[0].SrcPorts, pairs[0].DstPorts)
	}
}

func TestParseZonePairs_DstPortsOnly(t *testing.T) {
	cfg := &Config{ZonePairs: []string{"External->Internal:80,443"}}
	pairs, err := cfg.ParseZonePairs()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pairs[0].Src != "External" || pairs[0].Dst != "Internal" {
		t.Errorf("unexpected zone names: %+v", pairs[0])
	}
	if len(pairs[0].SrcPorts) != 0 {
		t.Errorf("expected empty SrcPorts, got %v", pairs[0].SrcPorts)
	}
	if len(pairs[0].DstPorts) != 2 || pairs[0].DstPorts[0] != 80 || pairs[0].DstPorts[1] != 443 {
		t.Errorf("expected DstPorts=[80,443], got %v", pairs[0].DstPorts)
	}
}

func TestParseZonePairs_SrcPortsOnly(t *testing.T) {
	cfg := &Config{ZonePairs: []string{"External:80->Internal"}}
	pairs, err := cfg.ParseZonePairs()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pairs[0].SrcPorts) != 1 || pairs[0].SrcPorts[0] != 80 {
		t.Errorf("expected SrcPorts=[80], got %v", pairs[0].SrcPorts)
	}
	if len(pairs[0].DstPorts) != 0 {
		t.Errorf("expected empty DstPorts, got %v", pairs[0].DstPorts)
	}
}

func TestParseZonePairs_SeparatePorts(t *testing.T) {
	cfg := &Config{ZonePairs: []string{"External:81,8443->Internal:80,443"}}
	pairs, err := cfg.ParseZonePairs()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pairs[0].Src != "External" || pairs[0].Dst != "Internal" {
		t.Errorf("unexpected zone names: %+v", pairs[0])
	}
	if len(pairs[0].SrcPorts) != 2 || pairs[0].SrcPorts[0] != 81 || pairs[0].SrcPorts[1] != 8443 {
		t.Errorf("expected SrcPorts=[81,8443], got %v", pairs[0].SrcPorts)
	}
	if len(pairs[0].DstPorts) != 2 || pairs[0].DstPorts[0] != 80 || pairs[0].DstPorts[1] != 443 {
		t.Errorf("expected DstPorts=[80,443], got %v", pairs[0].DstPorts)
	}
}

func TestParseZonePairs_InvalidPort_OutOfRange(t *testing.T) {
	cfg := &Config{ZonePairs: []string{"External->Internal:0"}}
	_, err := cfg.ParseZonePairs()
	if err == nil {
		t.Error("expected error for port 0 (out of range)")
	}
}

func TestParseZonePairs_InvalidPort_TooHigh(t *testing.T) {
	cfg := &Config{ZonePairs: []string{"External->Internal:65536"}}
	_, err := cfg.ParseZonePairs()
	if err == nil {
		t.Error("expected error for port 65536 (out of range)")
	}
}

func TestParseZonePairs_InvalidPort_NonNumeric(t *testing.T) {
	cfg := &Config{ZonePairs: []string{"External->Internal:http"}}
	_, err := cfg.ParseZonePairs()
	if err == nil {
		t.Error("expected error for non-numeric port")
	}
}

func TestParseCloudflareZonePairs(t *testing.T) {
	cfg := &Config{CloudflareZonePairs: []string{"External:81,8443->DMZ:80,443"}}
	pairs, err := cfg.ParseCloudflareZonePairs()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pairs) != 1 {
		t.Fatalf("expected 1 pair, got %d", len(pairs))
	}
	if pairs[0].Src != "External" || pairs[0].Dst != "DMZ" {
		t.Errorf("unexpected zone names: src=%q dst=%q", pairs[0].Src, pairs[0].Dst)
	}
	if len(pairs[0].SrcPorts) != 2 || pairs[0].SrcPorts[0] != 81 {
		t.Errorf("unexpected SrcPorts: %v", pairs[0].SrcPorts)
	}
	if len(pairs[0].DstPorts) != 2 || pairs[0].DstPorts[0] != 80 {
		t.Errorf("unexpected DstPorts: %v", pairs[0].DstPorts)
	}
}

func TestSplitZonePairList(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "empty",
			input: "",
			want:  nil,
		},
		{
			name:  "single simple pair",
			input: "External->Internal",
			want:  []string{"External->Internal"},
		},
		{
			name:  "multiple simple pairs comma-separated (backward compat)",
			input: "wan->lan,wan->iot,wan->dmz",
			want:  []string{"wan->lan", "wan->iot", "wan->dmz"},
		},
		{
			name:  "single pair with dst ports — commas are port separators",
			input: "External->Internal:80,443",
			want:  []string{"External->Internal:80,443"},
		},
		{
			name:  "single pair with src and dst ports",
			input: "External:80,443->Dmz:80,443",
			want:  []string{"External:80,443->Dmz:80,443"},
		},
		{
			name:  "multiple pairs with ports semicolon-separated",
			input: "External:80,443->Dmz:80,443;External->Corporate",
			want:  []string{"External:80,443->Dmz:80,443", "External->Corporate"},
		},
		{
			name:  "multiple simple pairs semicolon-separated",
			input: "External->Internal;External->DMZ",
			want:  []string{"External->Internal", "External->DMZ"},
		},
		{
			name:  "semicolon with whitespace",
			input: "External:80,443->Dmz ; External->Corporate",
			want:  []string{"External:80,443->Dmz", "External->Corporate"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := splitZonePairList(tc.input)
			if len(got) != len(tc.want) {
				t.Fatalf("len: got %d (%v), want %d (%v)", len(got), got, len(tc.want), tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("[%d]: got %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestZonePairsWithPortsViaLoad verifies that a CLOUDFLARE_ZONE_PAIRS value
// containing port-list commas is treated as a single zone pair by Load().
func TestZonePairsWithPortsViaLoad(t *testing.T) {
	setEnv(t, "UNIFI_URL", "https://192.168.1.1")
	setEnv(t, "UNIFI_API_KEY", "key")
	setEnv(t, "CROWDSEC_LAPI_KEY", "lapi-key")
	setEnv(t, "CLOUDFLARE_WHITELIST_ENABLED", "true")
	setEnv(t, "CLOUDFLARE_ZONE_PAIRS", "External:80,443->Dmz:80,443")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.CloudflareZonePairs) != 1 {
		t.Fatalf("expected 1 CloudflareZonePair, got %d: %v", len(cfg.CloudflareZonePairs), cfg.CloudflareZonePairs)
	}
	if cfg.CloudflareZonePairs[0] != "External:80,443->Dmz:80,443" {
		t.Errorf("CloudflareZonePairs[0]: got %q", cfg.CloudflareZonePairs[0])
	}
	pairs, err := cfg.ParseCloudflareZonePairs()
	if err != nil {
		t.Fatalf("ParseCloudflareZonePairs: %v", err)
	}
	if len(pairs) != 1 {
		t.Fatalf("expected 1 parsed pair, got %d", len(pairs))
	}
	if pairs[0].Src != "External" || pairs[0].Dst != "Dmz" {
		t.Errorf("unexpected zones: src=%q dst=%q", pairs[0].Src, pairs[0].Dst)
	}
	if len(pairs[0].SrcPorts) != 2 || pairs[0].SrcPorts[0] != 80 || pairs[0].SrcPorts[1] != 443 {
		t.Errorf("unexpected SrcPorts: %v", pairs[0].SrcPorts)
	}
	if len(pairs[0].DstPorts) != 2 || pairs[0].DstPorts[0] != 80 || pairs[0].DstPorts[1] != 443 {
		t.Errorf("unexpected DstPorts: %v", pairs[0].DstPorts)
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
	os.Unsetenv("ZONE_PAIRS")
	os.Unsetenv("GROUP_NAME_TEMPLATE")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.FirewallMode != "auto" {
		t.Errorf("default FirewallMode: got %q", cfg.FirewallMode)
	}
	if cfg.GroupNameTemplate != "crowdsec-block-{{.Family}}-{{.Index}}" {
		t.Errorf("default GroupNameTemplate: got %q", cfg.GroupNameTemplate)
	}
	if len(cfg.ZonePairs) != 1 || cfg.ZonePairs[0] != "External->Internal" {
		t.Errorf("default ZonePairs: got %v", cfg.ZonePairs)
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

func TestLoad_QuotedEnvValues(t *testing.T) {
	setEnv(t, "CROWDSEC_LAPI_KEY", "'test-key'")
	setEnv(t, "CROWDSEC_LAPI_URL", "'http://crowdsec:8080'")
	setEnv(t, "UNIFI_URL", "'https://192.168.1.1'")
	setEnv(t, "UNIFI_API_KEY", `"test-api-key"`)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load with quoted values: %v", err)
	}
	if cfg.CrowdSecLAPIKey != "test-key" {
		t.Errorf("CrowdSecLAPIKey: got %q, want %q", cfg.CrowdSecLAPIKey, "test-key")
	}
	if cfg.CrowdSecLAPIURL != "http://crowdsec:8080" {
		t.Errorf("CrowdSecLAPIURL: got %q, want %q", cfg.CrowdSecLAPIURL, "http://crowdsec:8080")
	}
	if cfg.UnifiURL != "https://192.168.1.1" {
		t.Errorf("UnifiURL: got %q, want %q", cfg.UnifiURL, "https://192.168.1.1")
	}
	if cfg.UnifiAPIKey != "test-api-key" {
		t.Errorf("UnifiAPIKey: got %q, want %q", cfg.UnifiAPIKey, "test-api-key")
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

func TestDeprecationAlias_FirewallBatchWindow(t *testing.T) {
	baseEnv(t)
	t.Setenv("FIREWALL_BATCH_WINDOW", "60s")
	os.Unsetenv("SYNC_INTERVAL")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SyncInterval.Seconds() != 60 {
		t.Errorf("expected SyncInterval=60s from FIREWALL_BATCH_WINDOW, got %s", cfg.SyncInterval)
	}
	if len(cfg.DeprecationWarnings) == 0 {
		t.Error("expected deprecation warning for FIREWALL_BATCH_WINDOW")
	}
}

func TestDeprecationAlias_SyncIntervalWins(t *testing.T) {
	baseEnv(t)
	t.Setenv("FIREWALL_BATCH_WINDOW", "60s")
	t.Setenv("SYNC_INTERVAL", "120s")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// SYNC_INTERVAL takes precedence over the deprecated FIREWALL_BATCH_WINDOW
	if cfg.SyncInterval.Seconds() != 120 {
		t.Errorf("expected SyncInterval=120s (SYNC_INTERVAL wins), got %s", cfg.SyncInterval)
	}
}

func TestInsecureLAPIURLWarning(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		verifyTLS bool
		wantWarn  bool
	}{
		// http:// — plaintext, always warn on non-loopback
		{name: "http_remote_ip", url: "http://1.2.3.4:8080", verifyTLS: true, wantWarn: true},
		{name: "http_remote_host", url: "http://crowdsec.internal:8080", verifyTLS: true, wantWarn: true},
		{name: "http_loopback_127", url: "http://127.0.0.1:8080", verifyTLS: true, wantWarn: false},
		{name: "http_loopback_localhost", url: "http://localhost:8080", verifyTLS: true, wantWarn: false},
		{name: "http_loopback_ipv6", url: "http://[::1]:8080", verifyTLS: true, wantWarn: false},

		// https:// + verify=true — safe, no warning regardless of host
		{name: "https_remote_verify_true", url: "https://1.2.3.4:8080", verifyTLS: true, wantWarn: false},
		{name: "https_remote_host_verify_true", url: "https://crowdsec.internal:8080", verifyTLS: true, wantWarn: false},
		{name: "https_loopback_verify_true", url: "https://127.0.0.1:8080", verifyTLS: true, wantWarn: false},

		// https:// + verify=false — MITM risk, warn on non-loopback
		{name: "https_remote_verify_false", url: "https://1.2.3.4:8080", verifyTLS: false, wantWarn: true},
		{name: "https_remote_host_verify_false", url: "https://crowdsec.internal:8080", verifyTLS: false, wantWarn: true},
		{name: "https_loopback_verify_false", url: "https://127.0.0.1:8080", verifyTLS: false, wantWarn: false},
		{name: "https_localhost_verify_false", url: "https://localhost:8080", verifyTLS: false, wantWarn: false},
		{name: "https_loopback_ipv6_verify_false", url: "https://[::1]:8080", verifyTLS: false, wantWarn: false},

		// Edge cases
		{name: "invalid_url", url: "://bad", verifyTLS: true, wantWarn: false},
		{name: "empty_url", url: "", verifyTLS: true, wantWarn: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				CrowdSecLAPIURL:       tc.url,
				CrowdSecLAPIVerifyTLS: tc.verifyTLS,
			}
			got := cfg.InsecureLAPIURLWarning()
			if tc.wantWarn && got == "" {
				t.Errorf("expected a warning for url=%q verifyTLS=%v, got none", tc.url, tc.verifyTLS)
			}
			if !tc.wantWarn && got != "" {
				t.Errorf("expected no warning for url=%q verifyTLS=%v, got: %q", tc.url, tc.verifyTLS, got)
			}
		})
	}
}

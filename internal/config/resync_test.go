package config

import (
	"strings"
	"testing"
	"time"
)

func TestCrowdSecResyncInterval(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    time.Duration
		wantErr bool
	}{
		{"default", "", time.Hour, false},
		{"disabled", "0s", 0, false},
		{"custom", "15m", 15 * time.Minute, false},
		{"too short", "30s", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setEnv(t, "UNIFI_URL", "https://192.168.1.1")
			setEnv(t, "UNIFI_API_KEY", "key")
			setEnv(t, "CROWDSEC_LAPI_KEY", "lapi-key")
			if tt.value != "" {
				setEnv(t, "CROWDSEC_RESYNC_INTERVAL", tt.value)
			}
			cfg, err := Load()
			if tt.wantErr {
				if err == nil || !strings.Contains(err.Error(), "CROWDSEC_RESYNC_INTERVAL") {
					t.Fatalf("err = %v, want CROWDSEC_RESYNC_INTERVAL error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.CrowdSecResyncInterval != tt.want {
				t.Fatalf("CrowdSecResyncInterval = %s, want %s", cfg.CrowdSecResyncInterval, tt.want)
			}
		})
	}
}

func TestCloudflareURLsValidated(t *testing.T) {
	for _, key := range []string{"CLOUDFLARE_IPV4_URL", "CLOUDFLARE_IPV6_URL"} {
		t.Run(key, func(t *testing.T) {
			setEnv(t, "UNIFI_URL", "https://192.168.1.1")
			setEnv(t, "UNIFI_API_KEY", "key")
			setEnv(t, "CROWDSEC_LAPI_KEY", "lapi-key")
			setEnv(t, "CLOUDFLARE_WHITELIST_ENABLED", "true")
			setEnv(t, "CLOUDFLARE_ZONE_PAIRS", "External->Internal")
			setEnv(t, key, "file:///etc/passwd")
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "CLOUDFLARE_IPV") {
				t.Fatalf("err = %v, want Cloudflare URL error", err)
			}
		})
	}
}

package config

import (
	"strings"
	"testing"
)

func TestBlocklistMinPrefix(t *testing.T) {
	tests := []struct {
		name         string
		v4, v6       string
		wantV4       int
		wantV6       int
		wantErrInKey string
	}{
		{name: "defaults", wantV4: 8, wantV6: 32},
		{name: "stricter", v4: "16", v6: "48", wantV4: 16, wantV6: 48},
		{name: "single hosts only", v4: "32", v6: "128", wantV4: 32, wantV6: 128},
		{name: "IPv4 broader than the default", v4: "7", wantErrInKey: "BLOCKLIST_MIN_PREFIX_V4"},
		{name: "IPv4 beyond a host", v4: "33", wantErrInKey: "BLOCKLIST_MIN_PREFIX_V4"},
		{name: "IPv6 broader than the default", v6: "31", wantErrInKey: "BLOCKLIST_MIN_PREFIX_V6"},
		{name: "IPv6 beyond a host", v6: "129", wantErrInKey: "BLOCKLIST_MIN_PREFIX_V6"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setEnv(t, "UNIFI_URL", "https://192.168.1.1")
			setEnv(t, "UNIFI_API_KEY", "key")
			setEnv(t, "CROWDSEC_LAPI_KEY", "lapi-key")
			if tt.v4 != "" {
				setEnv(t, "BLOCKLIST_MIN_PREFIX_V4", tt.v4)
			}
			if tt.v6 != "" {
				setEnv(t, "BLOCKLIST_MIN_PREFIX_V6", tt.v6)
			}
			cfg, err := Load()
			if tt.wantErrInKey != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrInKey) {
					t.Fatalf("err = %v, want %s error", err, tt.wantErrInKey)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.BlocklistMinPrefixV4 != tt.wantV4 || cfg.BlocklistMinPrefixV6 != tt.wantV6 {
				t.Fatalf("min prefixes = /%d, /%d; want /%d, /%d",
					cfg.BlocklistMinPrefixV4, cfg.BlocklistMinPrefixV6, tt.wantV4, tt.wantV6)
			}
		})
	}
}

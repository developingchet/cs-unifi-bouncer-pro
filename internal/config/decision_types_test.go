package config

import (
	"slices"
	"strings"
	"testing"
)

func TestBlockDecisionTypes(t *testing.T) {
	tests := []struct {
		raw     string
		want    []string
		wantErr string
	}{
		{"", []string{"ban"}, ""},
		{"ban", []string{"ban"}, ""},
		{"ban,captcha", []string{"ban", "captcha"}, ""},
		{" Ban , CAPTCHA ,ban", []string{"ban", "captcha"}, ""},
		{"ban,delete", nil, "is not a decision type"},
		{"ban,cap tcha", nil, "invalid decision type"},
		{"ban,captcha!", nil, "invalid decision type"},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			setEnv(t, "UNIFI_URL", "https://192.0.2.1")
			setEnv(t, "UNIFI_API_KEY", "key")
			setEnv(t, "CROWDSEC_LAPI_KEY", "key")
			if tt.raw == "" {
				unsetEnv(t, "BLOCK_DECISION_TYPES")
			} else {
				setEnv(t, "BLOCK_DECISION_TYPES", tt.raw)
			}
			cfg, err := Load()
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if !slices.Equal(cfg.BlockDecisionTypes, tt.want) {
				t.Fatalf("BlockDecisionTypes = %q, want %q", cfg.BlockDecisionTypes, tt.want)
			}
		})
	}
}

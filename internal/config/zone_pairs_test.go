package config

import (
	"strings"
	"testing"
)

func TestLoadRejectsDuplicateZonePairs(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		wantErr string
	}{
		{
			name:    "inbound pair with other ports",
			env:     map[string]string{"ZONE_PAIRS": "External->Internal:80;External->Internal:443"},
			wantErr: "ZONE_PAIRS names External->Internal more than once",
		},
		{
			name:    "inbound pair with other destination addresses",
			env:     map[string]string{"ZONE_PAIRS": "External->Dmz@10.0.0.1;External->Dmz@10.0.0.2"},
			wantErr: "ZONE_PAIRS names External->Dmz more than once",
		},
		{
			name:    "inbound pair twice for one site",
			env:     map[string]string{"UNIFI_SITES": "default,branch", "ZONE_PAIRS": "External->Dmz;branch/Wan->Lan:80;branch/Wan->Lan:443"},
			wantErr: `ZONE_PAIRS names Wan->Lan more than once for site "branch"`,
		},
		{
			name: "inbound pair once unprefixed and once for a site",
			env:  map[string]string{"UNIFI_SITES": "default,branch", "ZONE_PAIRS": "External->Dmz;branch/External->Dmz:443"},
		},
		{
			name: "same pair in ZONE_PAIRS and EGRESS_ZONE_PAIRS",
			env:  map[string]string{"ZONE_PAIRS": "External->Dmz", "EGRESS_ZONE_PAIRS": "External->Dmz"},
		},
		{
			name:    "cloudflare pair",
			env:     map[string]string{"CLOUDFLARE_WHITELIST_ENABLED": "true", "CLOUDFLARE_ZONE_PAIRS": "External->Internal:80;External->Internal:443"},
			wantErr: "CLOUDFLARE_ZONE_PAIRS names External->Internal more than once",
		},
		{
			name: "duplicate ZONE_PAIRS in legacy mode are not used",
			env:  map[string]string{"FIREWALL_MODE": "legacy", "ZONE_PAIRS": "External->Internal:80;External->Internal:443"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			baseEnv(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			_, err := Load()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Load: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Load = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

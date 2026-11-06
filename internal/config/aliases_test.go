package config

import (
	"slices"
	"strings"
	"testing"
)

func TestUnifiDialIPv6Aliases(t *testing.T) {
	tests := []struct {
		name        string
		env         map[string]string
		want        bool
		wantWarning string
	}{
		{"default", nil, false, ""},
		{"current name", map[string]string{"UNIFI_DIAL_IPV6": "true"}, true, ""},
		{"deprecated name", map[string]string{"ENABLE_IPV6": "true"}, true,
			"ENABLE_IPV6 is deprecated; use UNIFI_DIAL_IPV6 instead"},
		{"deprecated name false", map[string]string{"ENABLE_IPV6": "false"}, false,
			"ENABLE_IPV6 is deprecated; use UNIFI_DIAL_IPV6 instead"},
		{"current name wins", map[string]string{"UNIFI_DIAL_IPV6": "false", "ENABLE_IPV6": "true"}, false,
			"ENABLE_IPV6 is deprecated; use UNIFI_DIAL_IPV6 instead (UNIFI_DIAL_IPV6 is set, so ENABLE_IPV6 is ignored)"},
		{"firewall IPv6 is a separate setting", map[string]string{"FIREWALL_ENABLE_IPV6": "true"}, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setEnv(t, "UNIFI_URL", "https://192.0.2.1")
			setEnv(t, "UNIFI_API_KEY", "key")
			setEnv(t, "CROWDSEC_LAPI_KEY", "key")
			for _, key := range []string{"UNIFI_DIAL_IPV6", "ENABLE_IPV6", "FIREWALL_ENABLE_IPV6"} {
				unsetEnv(t, key)
			}
			for key, value := range tt.env {
				setEnv(t, key, value)
			}
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.UnifiDialIPv6 != tt.want {
				t.Errorf("UnifiDialIPv6 = %v, want %v", cfg.UnifiDialIPv6, tt.want)
			}
			warnings := slices.DeleteFunc(slices.Clone(cfg.DeprecationWarnings), func(w string) bool {
				return !strings.Contains(w, "IPV6")
			})
			var want []string
			if tt.wantWarning != "" {
				want = []string{tt.wantWarning}
			}
			if !slices.Equal(warnings, want) {
				t.Errorf("warnings = %q, want %q", warnings, want)
			}
		})
	}
}

func TestLoadRejectsInvalidEnableIPv6(t *testing.T) {
	for _, env := range []map[string]string{
		{"ENABLE_IPV6": "yes"},
		{"ENABLE_IPV6": "yes", "UNIFI_DIAL_IPV6": "true"},
	} {
		_, err := loadWith(t, env)
		want := `ENABLE_IPV6 must be true or false; got "yes"`
		if err == nil || err.Error() != want {
			t.Errorf("Load with %v: err = %v, want %q", env, err, want)
		}
	}
}

func TestShardCapacitiesDefaultLimit(t *testing.T) {
	cfg := Config{ShardLimitV6: 300}
	v4, v6 := cfg.ShardCapacities(500)
	if v4 != 500 || v6 != 300 {
		t.Fatalf("capacities = %d/%d, want 500/300", v4, v6)
	}
}

package config

import (
	"testing"
	"time"
)

func TestBlankDurationUsesDefault(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		got  func(*Config) time.Duration
		want time.Duration
	}{
		{"blank SYNC_INTERVAL", map[string]string{"SYNC_INTERVAL": ""},
			func(c *Config) time.Duration { return c.SyncInterval }, 30 * time.Second},
		{"quoted blank UNIFI_HTTP_TIMEOUT", map[string]string{"UNIFI_HTTP_TIMEOUT": `""`},
			func(c *Config) time.Duration { return c.UnifiHTTPTimeout }, 120 * time.Second},
		{"blank SYNC_INTERVAL lets FIREWALL_BATCH_WINDOW apply",
			map[string]string{"SYNC_INTERVAL": " ", "FIREWALL_BATCH_WINDOW": "45s"},
			func(c *Config) time.Duration { return c.SyncInterval }, 45 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseEnv(t)
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got := tt.got(cfg); got != tt.want {
				t.Errorf("duration = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestDurationKeysCoverEveryDurationField(t *testing.T) {
	keys := durationKeys()
	for _, want := range []string{"sync_interval", "unifi_http_timeout", "firewall_reconcile_interval"} {
		found := false
		for _, k := range keys {
			found = found || k == want
		}
		if !found {
			t.Errorf("durationKeys() lacks %q: %v", want, keys)
		}
	}
}

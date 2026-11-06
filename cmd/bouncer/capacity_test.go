package main

import (
	"os"
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
)

// capacitySettings are the environment variables that size a shard.
var capacitySettings = []string{
	"SHARD_LIMIT",
	"FIREWALL_GROUP_CAPACITY",
	"FIREWALL_GROUP_CAPACITY_V4",
	"FIREWALL_GROUP_CAPACITY_V6",
}

// loadWithCapacity loads the configuration with only the given capacity
// settings present in the environment.
func loadWithCapacity(t *testing.T, env map[string]string) *config.Config {
	t.Helper()
	t.Setenv("UNIFI_URL", "https://192.0.2.1")
	t.Setenv("UNIFI_API_KEY", "key")
	t.Setenv("CROWDSEC_LAPI_KEY", "key")
	for _, key := range capacitySettings {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
	for key, value := range env {
		t.Setenv(key, value)
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	return cfg
}

// TestShardCapacityCombinations pins the effective IPv4 and IPv6 shard
// capacity for every way the capacity settings combine, so renaming them
// cannot change the size of an existing installation's shards.
func TestShardCapacityCombinations(t *testing.T) {
	tests := []struct {
		name           string
		env            map[string]string
		wantV4, wantV6 int
	}{
		{"nothing set", nil, 10000, 10000},
		{"SHARD_LIMIT", map[string]string{"SHARD_LIMIT": "5000"}, 5000, 5000},
		{"shared capacity", map[string]string{"FIREWALL_GROUP_CAPACITY": "3000"}, 3000, 3000},
		{"shared capacity below SHARD_LIMIT", map[string]string{"FIREWALL_GROUP_CAPACITY": "3000", "SHARD_LIMIT": "5000"}, 3000, 3000},
		{"shared capacity above SHARD_LIMIT", map[string]string{"FIREWALL_GROUP_CAPACITY": "8000", "SHARD_LIMIT": "5000"}, 5000, 5000},
		{"shared capacity zero", map[string]string{"FIREWALL_GROUP_CAPACITY": "0"}, 10000, 10000},
		{"shared capacity zero with SHARD_LIMIT", map[string]string{"FIREWALL_GROUP_CAPACITY": "0", "SHARD_LIMIT": "5000"}, 5000, 5000},
		{"IPv4 override", map[string]string{"FIREWALL_GROUP_CAPACITY_V4": "2000"}, 2000, 10000},
		{"IPv6 override", map[string]string{"FIREWALL_GROUP_CAPACITY_V6": "1000"}, 10000, 1000},
		{"both overrides and shared", map[string]string{
			"FIREWALL_GROUP_CAPACITY_V4": "2000", "FIREWALL_GROUP_CAPACITY_V6": "1000", "FIREWALL_GROUP_CAPACITY": "3000",
		}, 2000, 1000},
		{"IPv4 override above SHARD_LIMIT", map[string]string{"FIREWALL_GROUP_CAPACITY_V4": "9000", "SHARD_LIMIT": "5000"}, 5000, 5000},
		{"IPv4 override zero falls back to shared", map[string]string{"FIREWALL_GROUP_CAPACITY_V4": "0", "FIREWALL_GROUP_CAPACITY": "3000"}, 3000, 3000},
		{"IPv4 override above shared", map[string]string{"FIREWALL_GROUP_CAPACITY_V4": "9000", "FIREWALL_GROUP_CAPACITY": "3000"}, 9000, 3000},
		{"mixed with SHARD_LIMIT", map[string]string{
			"FIREWALL_GROUP_CAPACITY_V4": "2000", "FIREWALL_GROUP_CAPACITY_V6": "0",
			"FIREWALL_GROUP_CAPACITY": "8000", "SHARD_LIMIT": "5000",
		}, 2000, 5000},
		{"IPv6 override above SHARD_LIMIT", map[string]string{
			"FIREWALL_GROUP_CAPACITY_V6": "9000", "FIREWALL_GROUP_CAPACITY": "0", "SHARD_LIMIT": "5000",
		}, 5000, 5000},
		{"SHARD_LIMIT between the overrides", map[string]string{
			"FIREWALL_GROUP_CAPACITY_V4": "2000", "FIREWALL_GROUP_CAPACITY_V6": "1000", "SHARD_LIMIT": "1500",
		}, 1500, 1000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v4, v6 := resolveCapacities(loadWithCapacity(t, tt.env))
			if v4 != tt.wantV4 || v6 != tt.wantV6 {
				t.Fatalf("capacities = %d/%d, want %d/%d", v4, v6, tt.wantV4, tt.wantV6)
			}
		})
	}
}

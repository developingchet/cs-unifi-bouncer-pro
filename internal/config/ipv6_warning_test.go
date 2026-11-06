package config

import "testing"

func TestUnenforcedIPv6Warning(t *testing.T) {
	tests := []struct {
		name   string
		cfg    Config
		warned bool
	}{
		{"IPv4-only destinations", Config{FirewallEnableIPv6: true, ZonePairs: []string{"External->Dmz@192.168.1.10"}}, true},
		{"IPv4 CIDR destinations on every pair", Config{FirewallEnableIPv6: true,
			ZonePairs: []string{"External->Dmz@10.0.1.0/24", "External->Internal:443@10.0.0.5"}}, true},
		{"a pair without destination addresses", Config{FirewallEnableIPv6: true,
			ZonePairs: []string{"External->Dmz@192.168.1.10", "External->Internal"}}, false},
		{"an IPv6 destination", Config{FirewallEnableIPv6: true, ZonePairs: []string{"External->Dmz@2001:db8::10"}}, false},
		{"an egress pair", Config{FirewallEnableIPv6: true, ZonePairs: []string{"External->Dmz@192.168.1.10"},
			EgressZonePairs: []string{"Dmz->External"}}, false},
		{"IPv6 off", Config{ZonePairs: []string{"External->Dmz@192.168.1.10"}}, false},
		{"legacy mode", Config{FirewallEnableIPv6: true, FirewallMode: "legacy",
			ZonePairs: []string{"External->Dmz@192.168.1.10"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.UnenforcedIPv6Warning() != ""; got != tt.warned {
				t.Errorf("warned = %v, want %v", got, tt.warned)
			}
		})
	}
}

package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestUnenforcedIPv6Warnings(t *testing.T) {
	tests := []struct {
		name   string
		cfg    Config
		warned []string
	}{
		{"IPv4-only destinations", Config{FirewallEnableIPv6: true, ZonePairs: []string{"External->Dmz@192.168.1.10"}},
			[]string{"default", "branch"}},
		{"IPv4 CIDR destinations on every pair", Config{FirewallEnableIPv6: true,
			ZonePairs: []string{"External->Dmz@10.0.1.0/24", "External->Internal:443@10.0.0.5"}}, []string{"default", "branch"}},
		{"a pair without destination addresses", Config{FirewallEnableIPv6: true,
			ZonePairs: []string{"External->Dmz@192.168.1.10", "External->Internal"}}, nil},
		{"an IPv6 destination", Config{FirewallEnableIPv6: true, ZonePairs: []string{"External->Dmz@2001:db8::10"}}, nil},
		{"an egress pair", Config{FirewallEnableIPv6: true, ZonePairs: []string{"External->Dmz@192.168.1.10"},
			EgressZonePairs: []string{"Dmz->External"}}, nil},
		{"IPv6 off", Config{ZonePairs: []string{"External->Dmz@192.168.1.10"}}, nil},
		{"legacy mode", Config{FirewallEnableIPv6: true, FirewallMode: "legacy",
			ZonePairs: []string{"External->Dmz@192.168.1.10"}}, nil},
		{"only the site whose own pairs are IPv4-only", Config{FirewallEnableIPv6: true,
			ZonePairs: []string{"External->Dmz", "branch/Wan->Lan@192.168.5.10"}}, []string{"branch"}},
		{"a site's own pairs cover IPv6", Config{FirewallEnableIPv6: true,
			ZonePairs: []string{"External->Dmz@192.168.1.10", "branch/Wan->Lan"}}, []string{"default"}},
		{"an egress pair for one site only", Config{FirewallEnableIPv6: true,
			ZonePairs:       []string{"External->Dmz@192.168.1.10"},
			EgressZonePairs: []string{"branch/Lan->Wan"}}, []string{"default"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var warned []string
			for _, w := range tt.cfg.UnenforcedIPv6Warnings([]string{"default", "branch"}) {
				site := w[strings.Index(w, `site "`)+len(`site "`):]
				warned = append(warned, site[:strings.Index(site, `"`)])
			}
			if !reflect.DeepEqual(warned, tt.warned) {
				t.Errorf("warned sites = %q, want %q", warned, tt.warned)
			}
		})
	}
}

func TestUnenforcedIPv6WarningNamesTheSite(t *testing.T) {
	cfg := Config{FirewallEnableIPv6: true, ZonePairs: []string{"External->Dmz@192.168.1.10"}}
	want := `FIREWALL_ENABLE_IPV6 is on, but every ZONE_PAIRS pair of site "default" is limited to IPv4 destination addresses ` +
		`and the site has no EGRESS_ZONE_PAIRS pair, so if it uses the zone-based firewall it has no policy to enforce IPv6 bans; ` +
		`set FIREWALL_ENABLE_IPV6=false or add a pair that IPv6 traffic can match`
	if got := cfg.UnenforcedIPv6Warnings([]string{"default"}); len(got) != 1 || got[0] != want {
		t.Errorf("warnings = %q, want [%q]", got, want)
	}
}

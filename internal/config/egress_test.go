package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseEgressZonePairs(t *testing.T) {
	cfg := &Config{EgressZonePairs: []string{"Dmz->External", "IoT->External:443,8443"}}
	pairs, err := cfg.ParseEgressZonePairs()
	if err != nil {
		t.Fatalf("ParseEgressZonePairs: %v", err)
	}
	want := []ZonePair{
		{Src: "Dmz", Dst: "External", Egress: true},
		{Src: "IoT", Dst: "External", DstPorts: []int{443, 8443}, Egress: true},
	}
	if !reflect.DeepEqual(pairs, want) {
		t.Fatalf("pairs = %+v, want %+v", pairs, want)
	}
}

func TestParseEgressZonePairsRejectsDestinationIPs(t *testing.T) {
	cfg := &Config{EgressZonePairs: []string{"Dmz->External@198.51.100.1"}}
	if _, err := cfg.ParseEgressZonePairs(); err == nil || !strings.Contains(err.Error(), "destination IP list") {
		t.Fatalf("err = %v, want a destination IP list error", err)
	}
}

func TestManagedZonePairsListsInboundThenEgress(t *testing.T) {
	cfg := &Config{ZonePairs: []string{"External->Dmz"}, EgressZonePairs: []string{"Dmz->External"}}
	pairs, err := cfg.ManagedZonePairs()
	if err != nil {
		t.Fatalf("ManagedZonePairs: %v", err)
	}
	want := []ZonePair{{Src: "External", Dst: "Dmz"}, {Src: "Dmz", Dst: "External", Egress: true}}
	if !reflect.DeepEqual(pairs, want) {
		t.Fatalf("pairs = %+v, want %+v", pairs, want)
	}
}

func TestLoadEgressSettings(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		wantErr string
	}{
		{name: "unset", env: map[string]string{}},
		{name: "zone pairs", env: map[string]string{"EGRESS_ZONE_PAIRS": "Dmz->External;IoT->External"}},
		{
			name:    "legacy mode",
			env:     map[string]string{"EGRESS_ZONE_PAIRS": "Dmz->External", "FIREWALL_MODE": "legacy"},
			wantErr: "FIREWALL_MODE=legacy",
		},
		{
			name:    "duplicate pair",
			env:     map[string]string{"EGRESS_ZONE_PAIRS": "Dmz->External;Dmz->External:443"},
			wantErr: "more than once",
		},
		{
			name:    "bad connection state",
			env:     map[string]string{"EGRESS_CONNECTION_STATES": "NEW,RELATED"},
			wantErr: "EGRESS_CONNECTION_STATES",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("UNIFI_URL", "https://192.168.1.1")
			t.Setenv("UNIFI_API_KEY", "key")
			t.Setenv("CROWDSEC_LAPI_KEY", "lapi-key")
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			cfg, err := Load()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Load = %v, want error containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			states, err := cfg.ParseEgressConnectionStates()
			if err != nil || !reflect.DeepEqual(states, []string{"NEW"}) {
				t.Fatalf("egress connection states = %v, %v; want [NEW]", states, err)
			}
		})
	}
}

func TestLoadEgressRequiresAPIKey(t *testing.T) {
	t.Setenv("UNIFI_URL", "https://192.168.1.1")
	unsetEnv(t, "UNIFI_API_KEY")
	t.Setenv("UNIFI_USERNAME", "admin")
	t.Setenv("UNIFI_PASSWORD", "secret")
	t.Setenv("CROWDSEC_LAPI_KEY", "lapi-key")
	t.Setenv("EGRESS_ZONE_PAIRS", "Dmz->External")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "EGRESS_ZONE_PAIRS requires UNIFI_API_KEY") {
		t.Fatalf("Load = %v, want an API key error", err)
	}
}

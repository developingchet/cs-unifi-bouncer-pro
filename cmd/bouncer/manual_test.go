package main

import (
	"strings"
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/decision"
)

func TestCrowdSecUnbanWarning(t *testing.T) {
	for _, tt := range []struct {
		value string
		want  string
	}{
		{"198.51.100.7", "cscli decisions delete --ip 198.51.100.7"},
		{"2001:db8::1", "cscli decisions delete --ip 2001:db8::1"},
		{"198.51.100.0/24", "cscli decisions delete --range 198.51.100.0/24"},
	} {
		if got := crowdSecUnbanWarning(tt.value); !strings.Contains(got, tt.want) {
			t.Errorf("crowdSecUnbanWarning(%q) = %q, want it to contain %q", tt.value, got, tt.want)
		}
	}
}

func TestCheckManualBan(t *testing.T) {
	whitelist, err := decision.ParseWhitelist([]string{"203.0.113.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		value   string
		want    string
		wantErr string
	}{
		{name: "public address", value: "198.51.100.7", want: "198.51.100.7"},
		{name: "public range", value: "198.51.100.0/24", want: "198.51.100.0/24"},
		{name: "host prefix is stored bare", value: "198.51.100.7/32", want: "198.51.100.7"},
		{name: "not an address", value: "gateway", wantErr: "invalid IP"},
		{name: "private address", value: "192.168.1.1", wantErr: "private"},
		{name: "loopback", value: "127.0.0.1", wantErr: "private"},
		{name: "private IPv6", value: "fd00::1", wantErr: "private"},
		{name: "whitelisted address", value: "203.0.113.9", wantErr: "BLOCK_WHITELIST"},
		{name: "range covering a whitelisted network", value: "203.0.0.0/16", wantErr: "BLOCK_WHITELIST"},
		{name: "range broader than /8", value: "64.0.0.0/7", wantErr: "too broad"},
		{name: "IPv6 range broader than /32", value: "2001:db8::/31", wantErr: "too broad"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := checkManualBan(tt.value, whitelist)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("checkManualBan(%q) error = %v, want one containing %q", tt.value, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("checkManualBan(%q): %v", tt.value, err)
			}
			if got != tt.want {
				t.Fatalf("checkManualBan(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

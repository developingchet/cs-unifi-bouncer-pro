package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/decision"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/rs/zerolog"
)

func TestManualMessagesStateWhatDryRunWouldDo(t *testing.T) {
	expires := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	tests := []struct {
		name   string
		got    string
		want   string
		unwant string
	}{
		{"ban", banMessage("203.0.113.9", 2, expires, false), "banned 203.0.113.9 across 2 site(s)", "would"},
		{"ban dry run", banMessage("203.0.113.9", 2, expires, true), "would ban 203.0.113.9 across 2 site(s)", "banned"},
		{"unban", unbanMessage("203.0.113.9", 2, false), "unbanned 203.0.113.9 from 2 site(s)", "would"},
		{"unban dry run", unbanMessage("203.0.113.9", 2, true), "would unban 203.0.113.9 from 2 site(s)", "unbanned"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(tt.got, tt.want) {
				t.Errorf("message %q does not contain %q", tt.got, tt.want)
			}
			if strings.Contains(tt.got, tt.unwant) {
				t.Errorf("message %q must not contain %q", tt.got, tt.unwant)
			}
		})
	}
}

func TestDrainWhitelist(t *testing.T) {
	const site = "default"
	const desc = "Managed by cs-unifi-bouncer-pro. Cloudflare whitelist. Do not edit manually."
	tests := []struct {
		name        string
		cfg         config.Config
		wantDeleted int
	}{
		{"deletes with an API key", config.Config{UnifiSites: []string{site}, UnifiAPIKey: "key"}, 2},
		{"previews in dry run", config.Config{UnifiSites: []string{site}, UnifiAPIKey: "key", DryRun: true}, 0},
		{"skips without an API key", config.Config{UnifiSites: []string{site}}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := testutil.NewMockController()
			ctrl.SetPolicies(site, []controller.ZonePolicy{
				{ID: "p1", Name: "crowdsec-whitelist-cloudflare-External-Dmz-v4", Description: desc, Action: "ALLOW"},
			})
			ctrl.SetTMLs(site, []controller.TrafficMatchingList{{ID: "t1", Name: "crowdsec-whitelist-cloudflare-v4"}})

			if err := drainWhitelist(context.Background(), &tt.cfg, ctrl, zerolog.Nop()); err != nil {
				t.Fatal(err)
			}
			deleted := ctrl.Calls("DeleteZonePolicy") + ctrl.Calls("DeleteTrafficMatchingList")
			if deleted != tt.wantDeleted {
				t.Errorf("deleted %d objects, want %d", deleted, tt.wantDeleted)
			}
		})
	}
}

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

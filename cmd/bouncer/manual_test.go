package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
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

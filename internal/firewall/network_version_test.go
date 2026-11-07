package firewall

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
)

func TestLoadInfrastructureLegacyOnZoneOnlyRelease(t *testing.T) {
	tests := []struct {
		name       string
		mode       string
		version    string
		versionErr error
		hasZones   bool
		wantErr    string
	}{
		{name: "legacy on 10.x", mode: "legacy", version: "10.6.106"},
		{name: "legacy on 11.x", mode: "legacy", version: "11.0.83", wantErr: "FIREWALL_MODE=legacy: UniFi Network 11.0.83"},
		{name: "auto without zones on 11.x", mode: "auto", version: "11.0.83", wantErr: "has no firewall zones"},
		{name: "auto with zones on 11.x", mode: "auto", version: "11.0.83", hasZones: true},
		{name: "legacy with an unreadable version", mode: "legacy", versionErr: errTest("HTTP 404")},
		{name: "legacy with an unparsable version", mode: "legacy", version: "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := defaultManagerConfig()
			cfg.FirewallMode = tt.mode
			cfg.ZoneCfg.ZonePairs = []config.ZonePair{{Src: "wan", Dst: "lan"}}
			mgr, ctrl, _ := newTestManager(t, cfg)
			ctrl.SetVersion(tt.version)
			if tt.versionErr != nil {
				ctrl.SetError("ApplicationVersion", tt.versionErr)
			}
			ctrl.SetHasFeature(testSite, controller.FeatureZoneBasedFirewall, tt.hasZones)

			err := mgr.LoadInfrastructure(context.Background(), []string{testSite})
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("LoadInfrastructure: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("LoadInfrastructure error = %v, want it to contain %q", err, tt.wantErr)
			}
			if got := ctrl.Calls("CreateFirewallGroup") + ctrl.Calls("CreateFirewallRule"); got != 0 {
				t.Errorf("legacy objects created on a zone-only release: %d", got)
			}
		})
	}
}

func TestLoadInfrastructureReadsVersionOnce(t *testing.T) {
	cfg := defaultManagerConfig()
	cfg.FirewallMode = "legacy"
	mgr, ctrl, _ := newTestManager(t, cfg)
	if err := mgr.LoadInfrastructure(context.Background(), []string{testSite, "branch"}); err != nil {
		t.Fatalf("LoadInfrastructure: %v", err)
	}
	if got := ctrl.Calls("ApplicationVersion"); got != 1 {
		t.Errorf("ApplicationVersion calls = %d, want 1", got)
	}
}

func TestCheckModeChange(t *testing.T) {
	tests := []struct {
		name       string
		mode       string
		version    string
		versionErr error
		hasZones   bool
		featureErr error
		wantReason string
	}{
		{name: "unchanged", mode: "auto", version: "10.6.106"},
		{name: "upgraded to 11", mode: "auto", version: "11.0.83", wantReason: "UniFi Network 11.0.83"},
		{name: "explicit legacy upgraded to 11", mode: "legacy", version: "11.0.83", wantReason: "applies only the zone-based firewall"},
		{name: "zones appeared", mode: "auto", version: "10.6.106", hasZones: true, wantReason: "now has firewall zones"},
		{
			name: "zones appeared for a session login", mode: "auto", version: "10.6.106",
			featureErr: &controller.ErrZoneFirewallNeedsAPIKey{Site: testSite}, wantReason: "needs UNIFI_API_KEY",
		},
		{name: "explicit legacy ignores zones", mode: "legacy", version: "10.6.106", hasZones: true},
		{name: "detection failure is retried", mode: "auto", version: "10.6.106", featureErr: errTest("HTTP 502")},
		{name: "version failure is retried", mode: "auto", versionErr: errTest("HTTP 404")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := defaultManagerConfig()
			cfg.FirewallMode = tt.mode
			mgr, ctrl, _ := newTestManager(t, cfg)
			if err := mgr.LoadInfrastructure(context.Background(), []string{testSite}); err != nil {
				t.Fatalf("LoadInfrastructure: %v", err)
			}

			ctrl.SetVersion(tt.version)
			if tt.versionErr != nil {
				ctrl.SetError("ApplicationVersion", tt.versionErr)
			}
			ctrl.SetHasFeature(testSite, controller.FeatureZoneBasedFirewall, tt.hasZones)
			if tt.featureErr != nil {
				ctrl.SetError("HasFeature", tt.featureErr)
			}

			err := mgr.CheckModeChange(context.Background())
			if tt.wantReason == "" {
				if err != nil {
					t.Fatalf("CheckModeChange: %v", err)
				}
				return
			}
			var changed *ModeChangeError
			if !errors.As(err, &changed) {
				t.Fatalf("CheckModeChange error = %v, want a *ModeChangeError", err)
			}
			if changed.Site != testSite || !strings.Contains(changed.Reason, tt.wantReason) {
				t.Errorf("ModeChangeError = %+v, want site %q and a reason containing %q", changed, testSite, tt.wantReason)
			}
		})
	}
}

func TestCheckModeChangeSkipsZoneSites(t *testing.T) {
	cfg := defaultManagerConfig()
	cfg.FirewallMode = "auto"
	cfg.ZoneCfg.ZonePairs = []config.ZonePair{{Src: "wan", Dst: "lan"}}
	mgr, ctrl, _ := newTestManager(t, cfg)
	ctrl.SetHasFeature(testSite, controller.FeatureZoneBasedFirewall, true)
	if err := mgr.LoadInfrastructure(context.Background(), []string{testSite}); err != nil {
		t.Fatalf("LoadInfrastructure: %v", err)
	}
	before := ctrl.Calls("ApplicationVersion") + ctrl.Calls("HasFeature")

	if err := mgr.CheckModeChange(context.Background()); err != nil {
		t.Fatalf("CheckModeChange: %v", err)
	}
	if got := ctrl.Calls("ApplicationVersion") + ctrl.Calls("HasFeature") - before; got != 0 {
		t.Errorf("zone-mode site re-checked with %d controller calls, want 0", got)
	}
}

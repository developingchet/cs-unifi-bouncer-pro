package main

import (
	"context"
	"errors"
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
)

func TestDiagnoseSiteZones(t *testing.T) {
	zones := []controller.Zone{{ID: "z1", Name: "Internal"}}
	tests := []struct {
		name         string
		mode         string
		hasZones     bool
		featureErr   error
		discoverErr  error
		wantOK       bool
		wantStatus   string // status of the last check
		wantDiscover bool
	}{
		{name: "auto legacy site skips zone listing", mode: "auto", wantOK: true, wantStatus: "PASS"},
		{name: "auto zone site lists zones", mode: "auto", hasZones: true, wantOK: true, wantStatus: "", wantDiscover: true},
		{name: "auto detection error fails", mode: "auto", featureErr: errors.New("needs API key"), wantStatus: "FAIL"},
		{name: "zone mode lists zones", mode: "zone", wantOK: true, wantStatus: "", wantDiscover: true},
		{name: "zone listing error fails", mode: "zone", discoverErr: errors.New("403"), wantStatus: "FAIL", wantDiscover: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := testutil.NewMockController()
			ctrl.SetHasFeature("default", controller.FeatureZoneBasedFirewall, tt.hasZones)
			ctrl.SetZones("default", zones)
			if tt.featureErr != nil {
				ctrl.SetError("HasFeature", tt.featureErr)
			}
			if tt.discoverErr != nil {
				ctrl.SetError("DiscoverZones", tt.discoverErr)
			}

			checks, ok := diagnoseSiteZones(context.Background(), ctrl, tt.mode, "default")
			if ok != tt.wantOK {
				t.Errorf("ok = %v, want %v (%+v)", ok, tt.wantOK, checks)
			}
			if got := checks[len(checks)-1].status; got != tt.wantStatus {
				t.Errorf("last status = %q, want %q (%+v)", got, tt.wantStatus, checks)
			}
			discovered := false
			for _, c := range checks {
				if c.name == "zone_discovery[default]" {
					discovered = true
				}
			}
			if discovered != tt.wantDiscover {
				t.Errorf("zone listing attempted = %v, want %v", discovered, tt.wantDiscover)
			}
		})
	}
}

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/rs/zerolog"
)

func TestCheckSitesExist(t *testing.T) {
	tests := []struct {
		name    string
		known   []string
		listErr error
		sites   []string
		wantErr string
	}{
		{name: "all present", known: []string{"default", "branch"}, sites: []string{"default", "branch"}},
		{name: "unknown site", known: []string{"default"}, sites: []string{"default", "Branch Office"}, wantErr: `site "Branch Office" is not on the controller; available sites: default`},
		{name: "listing fails", listErr: errors.New("forbidden"), sites: []string{"default"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := testutil.NewMockController()
			ctrl.SetDiscoveredSites(tt.known)
			if tt.listErr != nil {
				ctrl.SetError("DiscoverSites", tt.listErr)
			}
			err := checkSitesExist(context.Background(), ctrl, tt.sites, zerolog.Nop())
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("checkSitesExist() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("checkSitesExist() = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestProbeLAPI(t *testing.T) {
	tests := []struct {
		name       string
		auth       bool
		code       int
		wantPath   string
		wantStatus string
		wantKeyTip bool
	}{
		{name: "health ok", code: http.StatusOK, wantPath: "/health", wantStatus: "PASS"},
		{name: "health error", code: http.StatusServiceUnavailable, wantPath: "/health", wantStatus: "WARN"},
		{name: "authenticated ok", auth: true, code: http.StatusOK, wantPath: "/v1/decisions", wantStatus: "PASS"},
		{name: "unauthorized", auth: true, code: http.StatusUnauthorized, wantPath: "/v1/decisions", wantStatus: "FAIL", wantKeyTip: true},
		{name: "unknown bouncer key", auth: true, code: http.StatusForbidden, wantPath: "/v1/decisions", wantStatus: "FAIL", wantKeyTip: true},
		{name: "server error", auth: true, code: http.StatusInternalServerError, wantPath: "/v1/decisions", wantStatus: "WARN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tt.wantPath {
					t.Errorf("path = %s, want %s", r.URL.Path, tt.wantPath)
				}
				if hasKey := r.Header.Get("X-Api-Key") != ""; hasKey != tt.auth {
					t.Errorf("request carries the API key: %v, want %v", hasKey, tt.auth)
				}
				if ua := r.Header.Get("User-Agent"); !strings.HasPrefix(ua, "crowdsec-unifi-bouncer/") {
					t.Errorf("User-Agent = %q, want the bouncer's own", ua)
				}
				w.WriteHeader(tt.code)
			}))
			defer srv.Close()

			got := probeLAPI(context.Background(), &config.Config{CrowdSecLAPIURL: srv.URL, CrowdSecLAPIKey: "key"}, tt.auth)
			if got.status != tt.wantStatus {
				t.Fatalf("status = %q, want %q (%+v)", got.status, tt.wantStatus, got)
			}
			if hasTip := strings.Contains(got.detail, "check CROWDSEC_LAPI_KEY"); hasTip != tt.wantKeyTip {
				t.Fatalf("detail = %q, key tip = %v, want %v", got.detail, hasTip, tt.wantKeyTip)
			}
		})
	}
}

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

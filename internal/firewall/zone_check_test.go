package firewall

import (
	"context"
	"strings"
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/rs/zerolog"
)

func checkZonesFixture(t *testing.T) (*ZoneManager, *testutil.MockController) {
	t.Helper()
	ctrl := testutil.NewMockController()
	ctrl.SetZones("default", []controller.Zone{
		{ID: "z-ext", Name: "External", NetworkIDs: []string{"n-wan"}},
		{ID: "z-int", Name: "Internal", NetworkIDs: []string{"n-lan"}},
	})
	zm := NewZoneManager(ZoneConfig{ZonePairs: []config.ZonePair{{Src: "External", Dst: "Internal"}}},
		zoneTestNamer(t), ctrl, testutil.NewMockStore(), zerolog.Nop())
	return zm, ctrl
}

func TestCheckZonesNamesTheUnknownZone(t *testing.T) {
	zm, _ := checkZonesFixture(t)
	if err := zm.CheckZones(context.Background(), "default", []string{"External", "Internal"}); err != nil {
		t.Fatalf("CheckZones with known zones: %v", err)
	}
	err := zm.CheckZones(context.Background(), "default", []string{"External", "Nowhere"})
	if err == nil || !strings.Contains(err.Error(), `"Nowhere"`) {
		t.Fatalf("CheckZones = %v, want an error naming Nowhere", err)
	}
}

// A site on the legacy firewall answers zone lookups with the integration
// API's zone-based-firewall-not-configured error; zone settings do not apply
// to it, so the check passes.
func TestCheckZonesPassesALegacyFirewallSite(t *testing.T) {
	zm, ctrl := checkZonesFixture(t)
	ctrl.SetError("GetZoneID", &controller.ErrBadRequest{
		Body: `{"statusCode":400,"code":"api.firewall.zone-based-firewall-not-configured","message":"Zone Based Firewall is not configured"}`,
	})
	if err := zm.CheckZones(context.Background(), "default", []string{"External", "Nowhere"}); err != nil {
		t.Fatalf("CheckZones on a legacy firewall site: %v", err)
	}
}

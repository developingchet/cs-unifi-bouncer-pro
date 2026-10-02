package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/firewall"
	"github.com/rs/zerolog"
)

// zoneManagerProbe fails the test if a reload reaches the zone manager.
type zoneManagerProbe struct {
	firewall.Manager
	t *testing.T
}

func (p zoneManagerProbe) ZoneManager() *firewall.ZoneManager {
	p.t.Error("reload reached the zone manager although ZONE_PAIRS is empty")
	return nil
}

func (p zoneManagerProbe) Reconcile(context.Context, []string) (*firewall.ReconcileResult, error) {
	p.t.Error("reload reconciled although ZONE_PAIRS is empty")
	return nil, nil
}

// An empty ZONE_PAIRS on SIGHUP must leave the running configuration alone:
// applying it would delete every block policy the bouncer manages.
func TestReloadZonesKeepsConfigWhenZonePairsAreEmpty(t *testing.T) {
	t.Setenv("UNIFI_URL", "https://192.168.1.1")
	t.Setenv("UNIFI_API_KEY", "key")
	t.Setenv("CROWDSEC_LAPI_KEY", "lapi-key")
	t.Setenv("FIREWALL_MODE", "auto")
	t.Setenv("ZONE_PAIRS", "")

	var out bytes.Buffer
	log := zerolog.New(&out)
	reloadZones(context.Background(), &config.Config{UnifiSites: []string{"default"}}, zoneManagerProbe{t: t}, log)

	if !strings.Contains(out.String(), "keeping the current zone pairs") {
		t.Errorf("log output %q does not report the rejected reload", out.String())
	}
	if !strings.Contains(out.String(), `"level":"error"`) {
		t.Errorf("log output %q is not at error level", out.String())
	}
}

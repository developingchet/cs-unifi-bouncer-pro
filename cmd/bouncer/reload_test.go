package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/firewall"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
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

// reconcileProbe counts how a reload brings the controller in line.
type reconcileProbe struct {
	firewall.Manager
	zm         *firewall.ZoneManager
	reconciled int
	repaired   int
}

func (p *reconcileProbe) ZoneManager() *firewall.ZoneManager { return p.zm }

func (p *reconcileProbe) Reconcile(context.Context, []string) (*firewall.ReconcileResult, error) {
	p.reconciled++
	return &firewall.ReconcileResult{}, nil
}

func (p *reconcileProbe) RepairInfrastructure(context.Context, []string) error {
	p.repaired++
	return nil
}

func newReconcileProbe(t *testing.T) *reconcileProbe {
	t.Helper()
	t.Setenv("UNIFI_URL", "https://192.168.1.1")
	t.Setenv("UNIFI_API_KEY", "key")
	t.Setenv("CROWDSEC_LAPI_KEY", "lapi-key")
	t.Setenv("FIREWALL_MODE", "zone")
	t.Setenv("ZONE_PAIRS", "External->Internal")
	ctrl := testutil.NewMockController()
	ctrl.SetZones("default", []controller.Zone{
		{ID: "z-ext", Name: "External", NetworkIDs: []string{"n-wan"}},
		{ID: "z-int", Name: "Internal", NetworkIDs: []string{"n-lan"}},
	})
	namer, err := firewall.NewNamer("crowdsec-block-{{.Family}}-{{.Index}}", "crowdsec-drop-{{.Family}}-{{.Index}}",
		"crowdsec-policy-{{.SrcZone}}-{{.DstZone}}-{{.Family}}-{{.Index}}")
	if err != nil {
		t.Fatal(err)
	}
	zm := firewall.NewZoneManager(firewall.ZoneConfig{
		ZonePairs: []config.ZonePair{{Src: "External", Dst: "Internal"}},
	}, namer, ctrl, testutil.NewMockStore(), zerolog.Nop())
	return &reconcileProbe{zm: zm}
}

// A SIGHUP before the startup reconcile gate opens must not reconcile bans:
// the ban database may still be empty, and a reconcile would remove every
// enforced ban from the controller. The policies are repaired instead.
func TestReloadZonesBeforeTheGateOpensOnlyRepairsPolicies(t *testing.T) {
	probe := newReconcileProbe(t)
	var out bytes.Buffer
	reloadZones(context.Background(), &config.Config{UnifiSites: []string{"default"}}, probe,
		func() bool { return false }, zerolog.New(&out))
	if probe.reconciled != 0 {
		t.Errorf("reload reconciled %d times before the gate opened", probe.reconciled)
	}
	if probe.repaired != 1 {
		t.Errorf("policies repaired %d times, want 1; log: %s", probe.repaired, out.String())
	}
}

func TestReloadZonesAfterTheGateOpensReconciles(t *testing.T) {
	probe := newReconcileProbe(t)
	var out bytes.Buffer
	reloadZones(context.Background(), &config.Config{UnifiSites: []string{"default"}}, probe,
		func() bool { return true }, zerolog.New(&out))
	if probe.reconciled != 1 || probe.repaired != 0 {
		t.Errorf("reconciled %d, repaired %d; want a single reconcile; log: %s", probe.reconciled, probe.repaired, out.String())
	}
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
	reloadZones(context.Background(), &config.Config{UnifiSites: []string{"default"}}, zoneManagerProbe{t: t}, func() bool { return true }, log)

	if !strings.Contains(out.String(), "keeping the current zone pairs") {
		t.Errorf("log output %q does not report the rejected reload", out.String())
	}
	if !strings.Contains(out.String(), `"level":"error"`) {
		t.Errorf("log output %q is not at error level", out.String())
	}
}

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

// legacyProbe is a firewall manager whose sites all use legacy mode: it has
// no zone manager, and a reload must not reconcile or repair through it.
type legacyProbe struct {
	firewall.Manager
	t *testing.T
}

func (legacyProbe) ZoneManager() *firewall.ZoneManager { return nil }

func (p legacyProbe) Reconcile(context.Context, []string) (*firewall.ReconcileResult, error) {
	p.t.Error("reload reconciled a legacy deployment")
	return nil, nil
}

func (p legacyProbe) RepairInfrastructure(context.Context, []string) error {
	p.t.Error("reload repaired a legacy deployment")
	return nil
}

// reconcileProbe counts how a reload brings the controller in line.
type reconcileProbe struct {
	firewall.Manager
	zm         *firewall.ZoneManager
	ctrl       *testutil.MockController
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
	return &reconcileProbe{zm: zm, ctrl: ctrl}
}

// A SIGHUP before the startup reconcile gate opens must not reconcile bans:
// the ban database may still be empty, and a reconcile would remove every
// enforced ban from the controller. The policies are repaired instead.
func TestReloadZonesBeforeTheGateOpensOnlyRepairsPolicies(t *testing.T) {
	probe := newReconcileProbe(t)
	var out bytes.Buffer
	reloadZones(context.Background(), &config.Config{UnifiSites: []string{"default"}}, probe, nil,
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
	reloadZones(context.Background(), &config.Config{UnifiSites: []string{"default"}}, probe, nil,
		func() bool { return true }, zerolog.New(&out))
	if probe.reconciled != 1 || probe.repaired != 0 {
		t.Errorf("reconciled %d, repaired %d; want a single reconcile; log: %s", probe.reconciled, probe.repaired, out.String())
	}
}

// An empty ZONE_PAIRS on SIGHUP must leave the running configuration alone:
// applying it would delete every block policy the bouncer manages.
func TestReloadZonesKeepsConfigWhenZonePairsAreEmpty(t *testing.T) {
	probe := newReconcileProbe(t)
	t.Setenv("FIREWALL_MODE", "auto")
	t.Setenv("ZONE_PAIRS", "")

	var out bytes.Buffer
	log := zerolog.New(&out)
	reloadZones(context.Background(), &config.Config{UnifiSites: []string{"default"}}, probe, nil, func() bool { return true }, log)

	if probe.reconciled != 0 || probe.repaired != 0 {
		t.Errorf("reconciled %d, repaired %d; want neither", probe.reconciled, probe.repaired)
	}
	if !strings.Contains(out.String(), "keeping the current zone pairs") {
		t.Errorf("log output %q does not report the rejected reload", out.String())
	}
	if !strings.Contains(out.String(), `"level":"error"`) {
		t.Errorf("log output %q is not at error level", out.String())
	}
}

// A legacy deployment has no zone pairs, so an empty ZONE_PAIRS on SIGHUP is
// not an error there: the reload takes the legacy skip path.
func TestReloadZonesSkipsLegacyDeploymentsWithoutError(t *testing.T) {
	for _, mode := range []string{"legacy", "auto"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("UNIFI_URL", "https://192.168.1.1")
			t.Setenv("UNIFI_API_KEY", "key")
			t.Setenv("CROWDSEC_LAPI_KEY", "lapi-key")
			t.Setenv("FIREWALL_MODE", mode)
			t.Setenv("ZONE_PAIRS", "")

			var out bytes.Buffer
			reloadZones(context.Background(), &config.Config{UnifiSites: []string{"default"}}, legacyProbe{t: t}, nil,
				func() bool { return true }, zerolog.New(&out))

			if !strings.Contains(out.String(), "SIGHUP: ZoneManager not available (legacy mode?), skipping reload") {
				t.Errorf("log output %q does not take the legacy skip path", out.String())
			}
			if strings.Contains(out.String(), `"level":"error"`) {
				t.Errorf("log output %q has an error for a legacy deployment", out.String())
			}
		})
	}
}

// Two inbound pairs with the same zones share policy and filter list names.
// A reload that names one twice is refused like any invalid configuration.
func TestReloadZonesRejectsDuplicatePairs(t *testing.T) {
	probe := newReconcileProbe(t)
	t.Setenv("ZONE_PAIRS", "External->Internal:80;External->Internal:443")
	var out bytes.Buffer
	reloadZones(context.Background(), &config.Config{UnifiSites: []string{"default"}}, probe, nil,
		func() bool { return true }, zerolog.New(&out))
	if probe.reconciled != 0 || probe.repaired != 0 {
		t.Errorf("reconciled %d, repaired %d; want neither", probe.reconciled, probe.repaired)
	}
	if !strings.Contains(out.String(), "ZONE_PAIRS names External->Internal more than once") {
		t.Errorf("log output %q does not report the duplicate pair", out.String())
	}
}

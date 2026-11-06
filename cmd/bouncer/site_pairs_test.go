package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/firewall"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/rs/zerolog"
)

func TestZonePairRows(t *testing.T) {
	pairs := []config.ZonePair{{Src: "External", Dst: "Dmz"}, {Site: "branch", Src: "Wan", Dst: "Lan"}}
	tests := []struct {
		name  string
		cfg   config.Config
		pairs []config.ZonePair
		want  [][2]string
	}{
		{"no prefixes", config.Config{UnifiSites: []string{"default", "branch"}}, pairs[:1],
			[][2]string{{"zone_pairs", "External->Dmz"}}},
		{"listed sites", config.Config{UnifiSites: []string{"default", "branch"}}, pairs,
			[][2]string{{"zone_pairs[default]", "External->Dmz"}, {"zone_pairs[branch]", "Wan->Lan"}}},
		{"discovered sites", config.Config{UnifiSitesAuto: true}, pairs,
			[][2]string{{"zone_pairs[branch]", "Wan->Lan"}, {"zone_pairs[*]", "External->Dmz"}}},
		{"site left without pairs", config.Config{UnifiSites: []string{"default", "branch"}}, pairs[1:],
			[][2]string{{"zone_pairs[default]", "0 pair(s)"}, {"zone_pairs[branch]", "Wan->Lan"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := zonePairRows("zone_pairs", tt.pairs, &tt.cfg); !slices.Equal(got, tt.want) {
				t.Errorf("rows = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLogSitePairs(t *testing.T) {
	cfg := &config.Config{
		FirewallMode:    "auto",
		ZonePairs:       []string{"External->Dmz:443", "lab/Lab->Lan"},
		EgressZonePairs: []string{"Dmz->External"},
	}
	var out bytes.Buffer
	logSitePairs(cfg, []string{"default", "branch"}, zerolog.New(&out))

	want := []string{
		`{"level":"warn","message":"ZONE_PAIRS names site \"lab\", which is not among the managed sites (default, branch); its pairs apply to no site"}`,
		`{"level":"info","site":"default","zone_pairs":["External->Dmz:443"],"egress_zone_pairs":["Dmz->External"],"message":"zone pairs for site"}`,
		`{"level":"info","site":"branch","zone_pairs":["External->Dmz:443"],"egress_zone_pairs":["Dmz->External"],"message":"zone pairs for site"}`,
	}
	if got := strings.Split(strings.TrimSpace(out.String()), "\n"); !slices.Equal(got, want) {
		t.Errorf("log =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// The IPv6 warning names only the site whose own pairs are all limited to
// IPv4 destinations.
func TestLogSitePairsWarnsPerSiteAboutUnenforcedIPv6(t *testing.T) {
	cfg := &config.Config{
		FirewallMode:       "auto",
		FirewallEnableIPv6: true,
		ZonePairs:          []string{"External->Dmz", "branch/Wan->Lan@192.168.5.10"},
	}
	var out bytes.Buffer
	logSitePairs(cfg, []string{"default", "branch"}, zerolog.New(&out))
	if got := strings.Count(out.String(), "no policy to enforce IPv6 bans"); got != 1 {
		t.Fatalf("log has %d IPv6 warnings, want 1:\n%s", got, out.String())
	}
	if !strings.Contains(out.String(), `every ZONE_PAIRS pair of site \"branch\" is limited to IPv4`) {
		t.Errorf("log does not name site branch:\n%s", out.String())
	}
}

func TestLogSitePairsLogsNothingForLegacyMode(t *testing.T) {
	var out bytes.Buffer
	logSitePairs(&config.Config{FirewallMode: "legacy", ZonePairs: []string{"External->Dmz"}}, []string{"default"}, zerolog.New(&out))
	if out.Len() != 0 {
		t.Errorf("log = %s, want nothing: zone pairs are not used in legacy mode", out.String())
	}
}

// A SIGHUP reads a changed ZONE_PAIRS_FILE, and each site gets the pairs
// that apply to it.
func TestReloadZonesAppliesEachSitesPairs(t *testing.T) {
	file := filepath.Join(t.TempDir(), "zone_pairs")
	writePairs := func(content string) {
		t.Helper()
		if err := os.WriteFile(file, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writePairs("External->Internal\nbranch/Wan->Lan\n")
	t.Setenv("UNIFI_URL", "https://192.168.1.1")
	t.Setenv("UNIFI_API_KEY", "key")
	t.Setenv("CROWDSEC_LAPI_KEY", "lapi-key")
	t.Setenv("FIREWALL_MODE", "zone")
	t.Setenv("UNIFI_SITES", "default,branch")
	t.Setenv("ZONE_PAIRS_FILE", file)

	ctrl := testutil.NewMockController()
	ctrl.SetZones("default", []controller.Zone{{ID: "z-ext", Name: "External"}, {ID: "z-int", Name: "Internal"}})
	ctrl.SetZones("branch", []controller.Zone{{ID: "z-wan", Name: "Wan"}, {ID: "z-lan", Name: "Lan"}, {ID: "z-iot", Name: "Iot"}})
	namer, err := firewall.NewNamer("crowdsec-block-{{.Family}}-{{.Index}}", "crowdsec-drop-{{.Family}}-{{.Index}}",
		"crowdsec-policy-{{.SrcZone}}-{{.DstZone}}-{{.Family}}-{{.Index}}")
	if err != nil {
		t.Fatal(err)
	}
	zm := firewall.NewZoneManager(firewall.ZoneConfig{
		ZonePairs: []config.ZonePair{{Src: "External", Dst: "Internal"}},
	}, namer, ctrl, testutil.NewMockStore(), zerolog.Nop())
	probe := &reconcileProbe{zm: zm}
	running := &config.Config{UnifiSites: []string{"default", "branch"}}

	for _, step := range []struct {
		content, branchPairs string
	}{
		{"External->Internal\nbranch/Wan->Lan\n", `["Wan->Lan"]`},
		{"External->Internal\nbranch/Wan->Iot\n", `["Wan->Iot"]`},
	} {
		writePairs(step.content)
		var out bytes.Buffer
		reloadZones(context.Background(), running, probe, nil, func() bool { return true }, zerolog.New(&out))
		log := out.String()
		for _, line := range []string{
			`{"level":"info","site":"default","zone_pairs":["External->Internal"],"message":"zone pairs for site"}`,
			`{"level":"info","site":"branch","zone_pairs":` + step.branchPairs + `,"message":"zone pairs for site"}`,
			"zone pairs and policies reloaded successfully",
		} {
			if !strings.Contains(log, line) {
				t.Errorf("reload of %q: log lacks %s\nlog: %s", step.content, line, log)
			}
		}
	}
	if probe.reconciled != 2 {
		t.Errorf("reconciled %d times, want once per reload", probe.reconciled)
	}
}

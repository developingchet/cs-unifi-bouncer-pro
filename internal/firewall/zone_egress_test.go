package firewall

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	promtest "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/rs/zerolog"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
)

const (
	inboundPolicy = "crowdsec-policy-wan-lan-v4-0"
	egressPolicy  = "crowdsec-policy-egress-lan-wan-v4-0"
)

// egressSite sets up a zone-mode site with one v4 shard holding a ban, an
// inbound pair wan->lan and the given egress pairs.
func egressSite(t *testing.T, egress ...config.ZonePair) (Manager, *testutil.MockController) {
	t.Helper()
	return zoneSite(t, append([]config.ZonePair{{Src: "wan", Dst: "lan"}}, egress...))
}

// zoneSite sets up a zone-mode site with one v4 shard holding a ban and the
// given zone pairs.
func zoneSite(t *testing.T, pairs []config.ZonePair) (Manager, *testutil.MockController) {
	t.Helper()
	cfg := defaultManagerConfig()
	cfg.FirewallMode = "zone"
	cfg.ZoneCfg.ZonePairs = pairs
	cfg.ZoneCfg.ConnectionStates = []string{"NEW", "INVALID"}
	cfg.ZoneCfg.EgressConnectionStates = []string{"NEW"}
	mgr, ctrl, store := newTestManager(t, cfg)
	ctrl.SetTMLs(testSite, []controller.TrafficMatchingList{{
		ID: "tml-0", Name: "crowdsec-block-v4-0", Type: "IPV4_ADDRESSES",
		Items: []controller.TrafficMatchingListItem{{Type: "IP_ADDRESS", Value: "203.0.113.7"}},
	}})
	if err := store.BanRecord("203.0.113.7", time.Time{}, false); err != nil {
		t.Fatal(err)
	}
	if err := mgr.EnsureInfrastructure(context.Background(), []string{testSite}); err != nil {
		t.Fatalf("EnsureInfrastructure: %v", err)
	}
	return mgr, ctrl
}

func policiesByName(t *testing.T, ctrl *testutil.MockController) map[string]controller.ZonePolicy {
	t.Helper()
	policies, err := ctrl.ListZonePolicies(context.Background(), testSite)
	if err != nil {
		t.Fatal(err)
	}
	byName := make(map[string]controller.ZonePolicy, len(policies))
	for _, p := range policies {
		byName[p.Name] = p
	}
	return byName
}

func TestEgressPolicyMatchesBanListAsDestination(t *testing.T) {
	_, ctrl := egressSite(t, config.ZonePair{Src: "lan", Dst: "wan", Egress: true})
	byName := policiesByName(t, ctrl)

	in, ok := byName[inboundPolicy]
	if !ok {
		t.Fatalf("inbound policy missing: %v", byName)
	}
	if !reflect.DeepEqual(in.TrafficMatchingListIDs, []string{"tml-0"}) || in.DstIPTMLID != "" {
		t.Errorf("inbound policy lists = source %v, destination %q; want source [tml-0]", in.TrafficMatchingListIDs, in.DstIPTMLID)
	}

	out, ok := byName[egressPolicy]
	if !ok {
		t.Fatalf("egress policy missing: %v", byName)
	}
	if len(out.TrafficMatchingListIDs) != 0 || out.DstIPTMLID != "tml-0" {
		t.Errorf("egress policy lists = source %v, destination %q; want destination tml-0 only", out.TrafficMatchingListIDs, out.DstIPTMLID)
	}
	if out.SrcZone != "lan" || out.DstZone != "wan" || out.Action != "BLOCK" || !out.Enabled {
		t.Errorf("egress policy = %+v; want an enabled lan->wan BLOCK", out)
	}
	if !reflect.DeepEqual(out.ConnectionStateFilter, []string{"NEW"}) {
		t.Errorf("egress connection states = %v, want [NEW]", out.ConnectionStateFilter)
	}
	if got := promtest.ToFloat64(metrics.ZoneBlockPolicies.WithLabelValues("egress", testSite)); got != 1 {
		t.Errorf("egress policy gauge = %v, want 1", got)
	}
	if got := promtest.ToFloat64(metrics.ZoneBlockPolicies.WithLabelValues("inbound", testSite)); got != 1 {
		t.Errorf("inbound policy gauge = %v, want 1", got)
	}
}

func TestEgressPairOverInboundZonesKeepsItsOwnPorts(t *testing.T) {
	_, ctrl := zoneSite(t, []config.ZonePair{
		{Src: "wan", Dst: "lan", DstPorts: []int{22}},
		{Src: "wan", Dst: "lan", DstPorts: []int{443}, Egress: true},
	})
	lists, err := ctrl.ListTrafficMatchingLists(context.Background(), testSite)
	if err != nil {
		t.Fatal(err)
	}
	ports := make(map[string]string)
	for _, l := range lists {
		if len(l.Items) == 1 {
			ports[l.ID] = l.Items[0].Value
		}
	}
	byName := policiesByName(t, ctrl)
	if got := ports[byName[inboundPolicy].DstPortTMLID]; got != "22" {
		t.Errorf("inbound policy port = %q, want 22", got)
	}
	if got := ports[byName["crowdsec-policy-egress-wan-lan-v4-0"].DstPortTMLID]; got != "443" {
		t.Errorf("egress policy port = %q, want 443", got)
	}
}

func TestRemovedEgressPairDeletesItsPolicies(t *testing.T) {
	mgr, ctrl := egressSite(t, config.ZonePair{Src: "lan", Dst: "wan", Egress: true})
	ctx := context.Background()
	if err := mgr.ZoneManager().Reload(ctx, []string{testSite}, []config.ZonePair{{Src: "wan", Dst: "lan"}}); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if _, err := mgr.Reconcile(ctx, []string{testSite}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	byName := policiesByName(t, ctrl)
	if _, ok := byName[egressPolicy]; ok {
		t.Error("egress policy kept after its pair was removed")
	}
	if _, ok := byName[inboundPolicy]; !ok {
		t.Error("inbound policy deleted with the egress pair")
	}
}

func TestPrunedShardDeletesEgressPolicy(t *testing.T) {
	mgr, ctrl := egressSite(t, config.ZonePair{Src: "lan", Dst: "wan", Egress: true})
	if err := mgr.ZoneManager().DeletePoliciesForShard(context.Background(), testSite, false, 0); err != nil {
		t.Fatalf("DeletePoliciesForShard: %v", err)
	}
	if byName := policiesByName(t, ctrl); len(byName) != 0 {
		t.Errorf("policies left after the shard was pruned: %v", byName)
	}
}

func TestOrphanedListCleanupDeletesEgressPolicy(t *testing.T) {
	mgr, ctrl := egressSite(t, config.ZonePair{Src: "lan", Dst: "wan", Egress: true})
	mgr.(*managerImpl).deleteOrphanedReferencingObjects(context.Background(), testSite, "zone", "tml-0")
	if byName := policiesByName(t, ctrl); len(byName) != 0 {
		t.Errorf("policies referencing the orphaned list = %v, want none", byName)
	}
}

func TestEgressPolicyReplacedWhenPortsChange(t *testing.T) {
	mgr, ctrl := egressSite(t, config.ZonePair{Src: "lan", Dst: "wan", Egress: true})
	ctx := context.Background()
	pairs := []config.ZonePair{{Src: "wan", Dst: "lan"}, {Src: "lan", Dst: "wan", DstPorts: []int{4444}, Egress: true}}
	if err := mgr.ZoneManager().Reload(ctx, []string{testSite}, pairs); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if _, err := mgr.Reconcile(ctx, []string{testSite}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	byName := policiesByName(t, ctrl)
	out, ok := byName[egressPolicy]
	if !ok || out.DstIPTMLID != "tml-0" || out.DstPortTMLID == "" {
		t.Fatalf("egress policy after the port change = %+v (found %v); want the ban list and a port filter", out, ok)
	}
	for name := range byName {
		if strings.HasPrefix(name, stagedPolicyPrefix) {
			t.Errorf("staged copy %s left after the replacement", name)
		}
	}
}

func TestShadowingAllows(t *testing.T) {
	idx := func(i int) *int { return &i }
	block := controller.ZonePolicy{ID: "b", Name: egressPolicy, Index: idx(5), SrcZone: "lan", DstZone: "wan", IPVersion: "IPV4"}
	policies := map[string]controller.ZonePolicy{
		"b":       block,
		"before":  {ID: "before", Name: "allow-web", Enabled: true, Action: "ALLOW", Index: idx(2), SrcZone: "lan", DstZone: "wan", IPVersion: "BOTH"},
		"after":   {ID: "after", Name: "allow-later", Enabled: true, Action: "ALLOW", Index: idx(9), SrcZone: "lan", DstZone: "wan"},
		"off":     {ID: "off", Name: "allow-off", Action: "ALLOW", Index: idx(1), SrcZone: "lan", DstZone: "wan"},
		"other":   {ID: "other", Name: "allow-other", Enabled: true, Action: "ALLOW", Index: idx(1), SrcZone: "dmz", DstZone: "wan"},
		"v6":      {ID: "v6", Name: "allow-v6", Enabled: true, Action: "ALLOW", Index: idx(1), SrcZone: "lan", DstZone: "wan", IPVersion: "IPV6"},
		"owned":   {ID: "owned", Name: "crowdsec-cf", Enabled: true, Action: "ALLOW", Index: idx(1), SrcZone: "lan", DstZone: "wan", Description: "test"},
		"noorder": {ID: "noorder", Name: "allow-unordered", Enabled: true, Action: "ALLOW", SrcZone: "lan", DstZone: "wan"},
	}
	found := shadowingAllows("test", []controller.ZonePolicy{block}, policies)
	if len(found) != 1 || found[0].allow.ID != "before" {
		t.Fatalf("shadowing allows = %+v, want only allow-web", found)
	}

	var buf bytes.Buffer
	zm := &ZoneManager{log: zerolog.New(&buf)}
	zm.reportShadowingAllows(testSite, found)
	zm.reportShadowingAllows(testSite, found)
	if n := strings.Count(buf.String(), "allow-web"); n != 1 {
		t.Errorf("warnings for an unchanged set = %d, want 1", n)
	}
	zm.reportShadowingAllows(testSite, nil)
	zm.reportShadowingAllows(testSite, found)
	if n := strings.Count(buf.String(), "allow-web"); n != 2 {
		t.Errorf("warnings after the set changed back = %d, want 2", n)
	}
}

func TestLegacySiteWarnsEgressPairsHaveNoEffect(t *testing.T) {
	tests := []struct {
		name  string
		pairs []config.ZonePair
		warn  bool
	}{
		{name: "egress pair", pairs: []config.ZonePair{{Src: "wan", Dst: "lan"}, {Src: "lan", Dst: "wan", Egress: true}}, warn: true},
		{name: "inbound pairs only", pairs: []config.ZonePair{{Src: "wan", Dst: "lan"}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := defaultManagerConfig()
			cfg.ZoneCfg.ZonePairs = tc.pairs
			var buf bytes.Buffer
			mgr := NewManager(cfg, testutil.NewMockController(), testutil.NewMockStore(), managerTestNamer(t), zerolog.New(&buf))
			if err := mgr.EnsureInfrastructure(context.Background(), []string{testSite}); err != nil {
				t.Fatalf("EnsureInfrastructure: %v", err)
			}
			if got := strings.Contains(buf.String(), "EGRESS_ZONE_PAIRS has no effect"); got != tc.warn {
				t.Errorf("warned = %v, want %v; log: %s", got, tc.warn, buf.String())
			}
		})
	}
}

func TestEgressPolicyName(t *testing.T) {
	namer, err := NewNamer("crowdsec-block-{{.Family}}-{{.Index}}", "crowdsec-drop-{{.Family}}-{{.Index}}",
		"crowdsec-policy-{{.SrcZone}}-{{.DstZone}}-{{.Family}}-{{.Index}}")
	if err != nil {
		t.Fatal(err)
	}
	got, err := namer.EgressPolicyName(NameData{Family: "v6", Index: 2, SrcZone: "iot", DstZone: "external"})
	if err != nil {
		t.Fatal(err)
	}
	if want := "crowdsec-policy-egress-iot-external-v6-2"; got != want {
		t.Errorf("EgressPolicyName = %q, want %q", got, want)
	}
}

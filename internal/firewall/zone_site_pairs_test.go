package firewall

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/rs/zerolog"
)

const branchSite = "branch"

// twoSiteFixture is a controller with two sites whose zones share no names:
// testSite has External and Internal, branchSite has Wan, Lan and Iot.
type twoSiteFixture struct {
	ctrl   *testutil.MockController
	store  storage.Store
	zm     *ZoneManager
	shards map[string]*ShardManager
}

func newTwoSiteFixture(t *testing.T, pairs []config.ZonePair) *twoSiteFixture {
	t.Helper()
	ctrl := testutil.NewMockController()
	ctrl.SetZones(testSite, []controller.Zone{
		{ID: "z-ext", Name: "External", NetworkIDs: []string{}},
		{ID: "z-int", Name: "Internal", NetworkIDs: []string{"n-lan"}},
	})
	ctrl.SetZones(branchSite, []controller.Zone{
		{ID: "z-wan", Name: "Wan", NetworkIDs: []string{"n-wan"}},
		{ID: "z-lan", Name: "Lan", NetworkIDs: []string{"n-branch-lan"}},
		{ID: "z-iot", Name: "Iot", NetworkIDs: []string{"n-iot"}},
	})
	store := newBboltStore(t)
	f := &twoSiteFixture{
		ctrl:   ctrl,
		store:  store,
		zm:     NewZoneManager(ZoneConfig{ZonePairs: pairs, Description: "test"}, zoneTestNamer(t), ctrl, store, zerolog.Nop()),
		shards: make(map[string]*ShardManager),
	}
	for _, site := range []string{testSite, branchSite} {
		f.shards[site] = activeZoneShard(t, site, ctrl, store)
	}
	if err := f.zm.Bootstrap(context.Background(), []string{testSite, branchSite}); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	return f
}

// activeZoneShard returns a v4 shard manager for site with one active shard.
func activeZoneShard(t *testing.T, site string, ctrl controller.Controller, store storage.Store) *ShardManager {
	t.Helper()
	ctx := context.Background()
	sm := NewShardManager(site, false, 5, zoneTestNamer(t), ctrl, store, zerolog.Nop(), 0, false, "zone")
	if err := sm.EnsureShards(ctx); err != nil {
		t.Fatalf("EnsureShards: %v", err)
	}
	if _, err := sm.Add(ctx, "10.0.0.1"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := sm.FlushDirty(ctx); err != nil {
		t.Fatalf("FlushDirty: %v", err)
	}
	return sm
}

func (f *twoSiteFixture) ensureAll(t *testing.T) {
	t.Helper()
	for _, site := range []string{testSite, branchSite} {
		if err := f.zm.EnsurePolicies(context.Background(), site, f.shards[site], nil); err != nil {
			t.Fatalf("EnsurePolicies(%s): %v", site, err)
		}
	}
}

// policies returns the site's policy IDs by name.
func (f *twoSiteFixture) policies(t *testing.T, site string) map[string]string {
	t.Helper()
	listed, err := f.ctrl.ListZonePolicies(context.Background(), site)
	if err != nil {
		t.Fatal(err)
	}
	byName := make(map[string]string, len(listed))
	for _, p := range listed {
		byName[p.Name] = p.ID
	}
	return byName
}

// zonePairsOf returns the "src-dst" zone part of each policy name, sorted.
func zonePairsOf(policies map[string]string) []string {
	var pairs []string
	for name := range policies {
		rest := strings.TrimPrefix(name, "crowdsec-policy-")
		pairs = append(pairs, rest[:strings.LastIndex(rest[:strings.LastIndex(rest, "-")], "-")])
	}
	slices.Sort(pairs)
	return pairs
}

var twoSitePairs = []config.ZonePair{
	{Src: "External", Dst: "Internal"},
	{Site: branchSite, Src: "Wan", Dst: "Lan"},
}

func TestBootstrapResolvesEachSiteOwnZones(t *testing.T) {
	f := newTwoSiteFixture(t, twoSitePairs)

	f.zm.mu.RLock()
	defaultZones := slices.Sorted(maps.Keys(f.zm.zoneCache[testSite]))
	branchZones := slices.Sorted(maps.Keys(f.zm.zoneCache[branchSite]))
	f.zm.mu.RUnlock()
	if !slices.Equal(defaultZones, []string{"External", "Internal"}) {
		t.Errorf("%s zones = %v, want External and Internal", testSite, defaultZones)
	}
	if !slices.Equal(branchZones, []string{"Lan", "Wan"}) {
		t.Errorf("%s zones = %v, want Wan and Lan", branchSite, branchZones)
	}

	f.ensureAll(t)
	if got := zonePairsOf(f.policies(t, testSite)); !slices.Equal(got, []string{"External-Internal"}) {
		t.Errorf("%s block policies cover %v, want External-Internal only", testSite, got)
	}
	if got := zonePairsOf(f.policies(t, branchSite)); !slices.Equal(got, []string{"Wan-Lan"}) {
		t.Errorf("%s block policies cover %v, want Wan-Lan only", branchSite, got)
	}
	if got := f.ctrl.Calls("DeleteZonePolicy"); got != 0 {
		t.Errorf("DeleteZonePolicy called %d times; one site's sweep removed another's policies", got)
	}
}

func TestReloadChangingOneSiteLeavesTheOtherAlone(t *testing.T) {
	ctx := context.Background()
	f := newTwoSiteFixture(t, twoSitePairs)
	f.ensureAll(t)
	defaultBefore := f.policies(t, testSite)

	added := []config.ZonePair{
		{Src: "External", Dst: "Internal"},
		{Site: branchSite, Src: "Wan", Dst: "Lan"},
		{Site: branchSite, Src: "Wan", Dst: "Iot"},
	}
	if err := f.zm.Reload(ctx, []string{testSite, branchSite}, added); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	f.ensureAll(t)
	if got := f.policies(t, testSite); !maps.Equal(got, defaultBefore) {
		t.Errorf("%s policies changed by a reload of %s's pairs: %v, was %v", testSite, branchSite, got, defaultBefore)
	}
	if got := zonePairsOf(f.policies(t, branchSite)); !slices.Equal(got, []string{"Wan-Iot", "Wan-Lan"}) {
		t.Errorf("%s block policies cover %v, want Wan-Iot and Wan-Lan", branchSite, got)
	}

	removed := []config.ZonePair{
		{Src: "External", Dst: "Internal"},
		{Site: branchSite, Src: "Wan", Dst: "Iot"},
	}
	if err := f.zm.Reload(ctx, []string{testSite, branchSite}, removed); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	f.ensureAll(t)
	if got := f.policies(t, testSite); !maps.Equal(got, defaultBefore) {
		t.Errorf("%s policies changed by a reload of %s's pairs: %v, was %v", testSite, branchSite, got, defaultBefore)
	}
	if got := zonePairsOf(f.policies(t, branchSite)); !slices.Equal(got, []string{"Wan-Iot"}) {
		t.Errorf("%s block policies cover %v after Wan->Lan was removed, want Wan-Iot only", branchSite, got)
	}
}

// Once a pair is removed from one site, only that site's own sweep deletes
// its policies: the sweep of another site leaves them, and their stored
// records, alone.
func TestOrphanSweepRemovesOnlyItsOwnSitesPolicies(t *testing.T) {
	ctx := context.Background()
	f := newTwoSiteFixture(t, twoSitePairs)
	f.ensureAll(t)
	branchBefore := f.policies(t, branchSite)

	reloaded := []config.ZonePair{
		{Src: "External", Dst: "Internal"},
		{Site: branchSite, Src: "Wan", Dst: "Iot"},
	}
	if err := f.zm.Reload(ctx, []string{testSite, branchSite}, reloaded); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if err := f.zm.EnsurePolicies(ctx, testSite, f.shards[testSite], nil); err != nil {
		t.Fatalf("EnsurePolicies(%s): %v", testSite, err)
	}
	if got := f.policies(t, branchSite); !maps.Equal(got, branchBefore) {
		t.Errorf("%s policies = %v after the %s sweep, want %v", branchSite, got, testSite, branchBefore)
	}
	if got := f.ctrl.Calls("DeleteZonePolicy"); got != 0 {
		t.Errorf("DeleteZonePolicy called %d times by the %s sweep", got, testSite)
	}
	for name := range branchBefore {
		if rec, err := getCachedPolicy(f.store, branchSite, name); err != nil || rec == nil {
			t.Errorf("record of %s policy %s = %v, %v; want it kept", branchSite, name, rec, err)
		}
	}

	if err := f.zm.EnsurePolicies(ctx, branchSite, f.shards[branchSite], nil); err != nil {
		t.Fatalf("EnsurePolicies(%s): %v", branchSite, err)
	}
	if got := zonePairsOf(f.policies(t, branchSite)); !slices.Equal(got, []string{"Wan-Iot"}) {
		t.Errorf("%s block policies cover %v, want Wan-Iot only", branchSite, got)
	}
	for name := range branchBefore {
		if rec, err := getCachedPolicy(f.store, branchSite, name); err != nil || rec != nil {
			t.Errorf("record of removed policy %s = %v, %v; want it gone", name, rec, err)
		}
	}
}

func TestReloadRejectsSiteLeftWithoutPairs(t *testing.T) {
	f := newTwoSiteFixture(t, twoSitePairs)
	onlyBranch := []config.ZonePair{{Site: branchSite, Src: "Wan", Dst: "Lan"}}
	err := f.zm.Reload(context.Background(), []string{testSite, branchSite}, onlyBranch)
	if !errors.Is(err, errNoZonePairs) || !strings.Contains(err.Error(), `site "`+testSite+`"`) {
		t.Fatalf("Reload error = %v, want errNoZonePairs for %s", err, testSite)
	}
	if got := f.zm.sitePairs(testSite); len(got) != 1 || got[0].Src != "External" {
		t.Errorf("%s pairs after a rejected reload = %+v, want the original pair", testSite, got)
	}
}

func TestLoadInfrastructureRejectsZoneSiteWithoutItsPairs(t *testing.T) {
	cfg := defaultManagerConfig()
	cfg.FirewallMode = "zone"
	cfg.ZoneCfg.ZonePairs = []config.ZonePair{{Site: branchSite, Src: "Wan", Dst: "Lan"}}
	mgr, _, _ := newTestManager(t, cfg)

	err := mgr.LoadInfrastructure(context.Background(), []string{testSite})
	if !errors.Is(err, errNoZonePairs) {
		t.Fatalf("LoadInfrastructure error = %v, want errNoZonePairs", err)
	}
}

package firewall

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/whitelist"
	"github.com/rs/zerolog"
)

func TestZoneManager_RecreatePolicies(t *testing.T) {
	ctx := context.Background()
	ctrl := testutil.NewMockController()
	store := testutil.NewMockStore()
	v4 := ensuredZoneV4Shard(t, ctrl, store)
	zm := NewZoneManager(ZoneConfig{
		ZonePairs:   []config.ZonePair{{Src: "wan", Dst: "lan", DstPorts: []int{443}, DstIPs: []string{"10.0.5.251"}}},
		Description: "test",
	}, zoneTestNamer(t), ctrl, store, zerolog.Nop())
	if err := zm.Bootstrap(ctx, []string{testSite}); err != nil {
		t.Fatal(err)
	}
	if err := zm.EnsurePolicies(ctx, testSite, v4, nil); err != nil {
		t.Fatal(err)
	}
	policies, err := ctrl.ListZonePolicies(ctx, testSite)
	if err != nil || len(policies) != 1 {
		t.Fatalf("setup: %+v, %v", policies, err)
	}
	owned := policies[0]
	foreign := controller.ZonePolicy{ID: "foreign", Name: owned.Name + "-user", Action: "BLOCK", Description: "someone else",
		SrcZone: owned.SrcZone, DstZone: owned.DstZone, IPVersion: "IPV4", TrafficMatchingListIDs: owned.TrafficMatchingListIDs}
	ctrl.SetPolicies(testSite, []controller.ZonePolicy{owned, foreign})

	err = zm.RecreatePolicies(ctx, testSite, []string{owned.ID, foreign.ID, "missing"})
	if err == nil || !strings.Contains(err.Error(), "not managed by this bouncer") || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("RecreatePolicies err = %v, want the foreign and missing policies refused", err)
	}
	if got := ctrl.Calls("UpdateZonePolicy"); got != 0 {
		t.Errorf("UpdateZonePolicy calls: got %d, want 0 (a PUT drops the filters)", got)
	}
	policies, err = ctrl.ListZonePolicies(ctx, testSite)
	if err != nil {
		t.Fatal(err)
	}
	var recreated *controller.ZonePolicy
	for i, p := range policies {
		switch {
		case strings.HasPrefix(p.Name, stagedPolicyPrefix):
			t.Errorf("staged copy %s left behind", p.Name)
		case p.ID == foreign.ID:
		case p.Name == owned.Name:
			recreated = &policies[i]
		default:
			t.Errorf("unexpected policy %+v", p)
		}
	}
	if len(policies) != 2 || recreated == nil {
		t.Fatalf("policies after recreate = %+v, want the foreign one and the recreated block", policies)
	}
	if recreated.ID == owned.ID {
		t.Errorf("block kept ID %s, want a new policy", owned.ID)
	}
	if recreated.DstPortTMLID != owned.DstPortTMLID || recreated.DstIPTMLID != owned.DstIPTMLID ||
		recreated.TrafficMatchingListIDs[0] != owned.TrafficMatchingListIDs[0] || !recreated.Enabled {
		t.Errorf("recreated = %+v, want the filters and group of %+v", *recreated, owned)
	}
	if err := zm.EnsurePolicies(ctx, testSite, v4, nil); err != nil {
		t.Fatalf("EnsurePolicies after recreate: %v", err)
	}
	if got := ctrl.Calls("CreateZonePolicy"); got != 3 {
		t.Errorf("CreateZonePolicy calls: got %d, want 3 (original, staged copy, replacement)", got)
	}
}

// TestCloudflareAllowAddedAfterBlocksPrecedesThem enables the whitelist on a
// pair whose block policies already exist, with the controller ordering
// policies by creation: the blocks are recreated behind the ALLOW policies.
func TestCloudflareAllowAddedAfterBlocksPrecedesThem(t *testing.T) {
	ctx := context.Background()
	ctrl := testutil.NewMockController()
	ctrl.OrderPoliciesOnCreate()
	store := testutil.NewMockStore()
	v4 := ensuredZoneV4Shard(t, ctrl, store)
	zm := NewZoneManager(ZoneConfig{
		ZonePairs:   []config.ZonePair{{Src: "wan", Dst: "lan", DstPorts: []int{443}}},
		Description: "test",
	}, zoneTestNamer(t), ctrl, store, zerolog.Nop())
	if err := zm.Bootstrap(ctx, []string{testSite}); err != nil {
		t.Fatal(err)
	}
	if err := zm.EnsurePolicies(ctx, testSite, v4, nil); err != nil {
		t.Fatal(err)
	}

	cf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "v6") {
			_, _ = w.Write([]byte("2606:4700::/32\n"))
			return
		}
		_, _ = w.Write([]byte("173.245.48.0/20\n"))
	}))
	defer cf.Close()
	wl := whitelist.NewManager(ctrl, []string{testSite}, whitelist.NewCloudflareProvider(cf.URL+"/v4", cf.URL+"/v6"), zerolog.Nop())
	wl.SetBlockRecreator(zm)
	pair := whitelist.ZonePairConfig{SrcName: "wan", DstName: "lan", SrcZoneID: "wan", DstZoneID: "lan"}
	if err := wl.Sync(ctx, []whitelist.ZonePairConfig{pair}); err != nil {
		t.Fatalf("whitelist Sync: %v", err)
	}

	policies, err := ctrl.ListZonePolicies(ctx, testSite)
	if err != nil {
		t.Fatal(err)
	}
	var allowV4, block *controller.ZonePolicy
	for i, p := range policies {
		switch {
		case p.Action == "ALLOW" && p.IPVersion == "IPV4":
			allowV4 = &policies[i]
		case p.Action == "BLOCK":
			if block != nil {
				t.Fatalf("more than one block policy left: %+v", policies)
			}
			block = &policies[i]
		}
	}
	if allowV4 == nil || block == nil {
		t.Fatalf("policies = %+v, want a v4 ALLOW and one block", policies)
	}
	if *block.Index <= *allowV4.Index {
		t.Errorf("block index %d, allow index %d: the block still precedes the allow", *block.Index, *allowV4.Index)
	}
	if block.DstPortTMLID == "" {
		t.Error("recreated block lost its destination port filter")
	}

	// A second sync finds the order correct and recreates nothing.
	creates := ctrl.Calls("CreateZonePolicy")
	if err := wl.Sync(ctx, []whitelist.ZonePairConfig{pair}); err != nil {
		t.Fatalf("second whitelist Sync: %v", err)
	}
	if got := ctrl.Calls("CreateZonePolicy"); got != creates {
		t.Errorf("second sync created %d policies, want none", got-creates)
	}
}

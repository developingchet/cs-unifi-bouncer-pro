package whitelist

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/rs/zerolog"
)

// reindexingRecreator stands in for the block policy manager. When moves is
// set, each recreated policy gets an index after every existing one, as the
// controller assigns to a new policy.
type reindexingRecreator struct {
	ctrl  *testutil.MockController
	moves bool
	err   error
	ids   []string
}

func (r *reindexingRecreator) RecreatePolicies(ctx context.Context, site string, ids []string) error {
	r.ids = append(r.ids, ids...)
	if !r.moves {
		return r.err
	}
	policies, err := r.ctrl.ListZonePolicies(ctx, site)
	if err != nil {
		return err
	}
	next := 1000
	for i := range policies {
		if slices.Contains(ids, policies[i].ID) {
			n := next
			next++
			policies[i].Index = &n
		}
	}
	r.ctrl.SetPolicies(site, policies)
	return r.err
}

func TestSyncSite_BlocksAheadOfAllow(t *testing.T) {
	tests := []struct {
		name      string
		recreator *reindexingRecreator
		wantIDs   []string
		wantErr   bool
	}{
		{name: "without a recreator the order is reported", wantErr: true},
		{name: "recreated blocks follow the allow", recreator: &reindexingRecreator{moves: true}, wantIDs: []string{"block-v4", "block-v6"}},
		{name: "blocks still ahead after recreating", recreator: &reindexingRecreator{err: errors.New("recreate failed")}, wantIDs: []string{"block-v4", "block-v6"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := testutil.NewMockController()
			mgr := NewManager(ctrl, []string{"s"}, NewCloudflareProvider("", ""), zerolog.Nop())
			if tt.recreator != nil {
				tt.recreator.ctrl = ctrl
				mgr.SetBlockRecreator(tt.recreator)
			}
			seedMisorderedSite(ctrl)
			pair := ZonePairConfig{SrcName: "External", DstName: "Dmz", SrcZoneID: "z-ext", DstZoneID: "z-dmz"}

			err := mgr.syncSite(context.Background(), "s", []string{"1.1.1.0/24"}, []string{"2606:4700::/32"}, []ZonePairConfig{pair})
			if tt.wantErr != (err != nil) {
				t.Fatalf("syncSite err = %v, want error: %v", err, tt.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), "follows block") {
				t.Errorf("syncSite err = %v, want the allow-after-block error", err)
			}
			if tt.recreator != nil && !slices.Equal(tt.recreator.ids, tt.wantIDs) {
				t.Errorf("recreated %v, want %v", tt.recreator.ids, tt.wantIDs)
			}
		})
	}
}

// seedMisorderedSite lists v4 and v6 blocks for External->Dmz created before
// the Cloudflare allows, plus a block of another pair that must be left alone.
func seedMisorderedSite(ctrl *testutil.MockController) {
	idx := func(i int) *int { return &i }
	ctrl.SetTMLs("s", []controller.TrafficMatchingList{
		{ID: "tml-v4", Name: TMLNameV4, Type: "IPV4_ADDRESSES", Items: []controller.TrafficMatchingListItem{{Type: "SUBNET", Value: "1.1.1.0/24"}}},
		{ID: "tml-v6", Name: TMLNameV6, Type: "IPV6_ADDRESSES", Items: []controller.TrafficMatchingListItem{{Type: "SUBNET", Value: "2606:4700::/32"}}},
	})
	allow := func(id, name, ipVersion, tml string, index int) controller.ZonePolicy {
		return controller.ZonePolicy{ID: id, Name: name, Enabled: true, Action: "ALLOW", AllowReturnTraffic: true,
			SrcZone: "z-ext", DstZone: "z-dmz", IPVersion: ipVersion, Description: whitelistDescription,
			TrafficMatchingListIDs: []string{tml}, Index: idx(index)}
	}
	block := func(id, dstZone, ipVersion string, index int) controller.ZonePolicy {
		return controller.ZonePolicy{ID: id, Name: "crowdsec-policy-" + id, Enabled: true, Action: "BLOCK",
			IPVersion: ipVersion, SrcZone: "z-ext", DstZone: dstZone, Index: idx(index)}
	}
	ctrl.SetPolicies("s", []controller.ZonePolicy{
		block("block-v4", "z-dmz", "IPV4", 100),
		block("block-v6", "z-dmz", "IPV6", 101),
		block("block-other-pair", "z-lan", "IPV4", 102),
		allow("allow-v4", "crowdsec-whitelist-cloudflare-External-Dmz-v4", "IPV4", "tml-v4", 200),
		allow("allow-v6", "crowdsec-whitelist-cloudflare-External-Dmz-v6", "IPV6", "tml-v6", 201),
	})
}

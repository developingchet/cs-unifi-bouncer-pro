package whitelist

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/rs/zerolog"
)

func cloudflareTestProvider(t *testing.T) *CloudflareProvider {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "v6") {
			_, _ = w.Write([]byte("2606:4700::/32\n"))
			return
		}
		_, _ = w.Write([]byte("173.245.48.0/20\n"))
	}))
	t.Cleanup(srv.Close)
	provider := NewCloudflareProvider(srv.URL+"/ips-v4", srv.URL+"/ips-v6")
	provider.HTTPClient = srv.Client()
	return provider
}

func whitelistPolicyNames(t *testing.T, ctrl controller.Controller, site string) []string {
	t.Helper()
	policies, err := ctrl.ListZonePolicies(context.Background(), site)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range policies {
		names = append(names, p.Name)
	}
	slices.Sort(names)
	return names
}

// Each site gets the ALLOW policies of the pairs that apply to it. A site
// that other sites' pairs leave without one has its whitelist removed.
func TestSyncAppliesEachSitesOwnPairs(t *testing.T) {
	ctrl := testutil.NewMockController()
	ctrl.SetPolicies("default", []controller.ZonePolicy{{
		ID: "old-allow", Name: whitelistPrefix + "External-Dmz-v4", Description: whitelistDescription,
		Enabled: true, Action: "ALLOW",
	}})
	ctrl.SetTMLs("default", []controller.TrafficMatchingList{{ID: "old-list", Name: TMLNameV4, Type: "IPV4_ADDRESSES"}})
	mgr := NewManager(ctrl, []string{"default", "branch", "lab"}, cloudflareTestProvider(t), zerolog.Nop())
	mgr.SetIPv6(false)
	pairs := []ZonePairConfig{
		{Site: "branch", SrcName: "Wan", DstName: "Lan"},
		{Site: "lab", SrcName: "Lab", DstName: "Web", DstPorts: []int{443}},
	}

	if err := mgr.Sync(context.Background(), pairs); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if got := whitelistPolicyNames(t, ctrl, "branch"); !slices.Equal(got, []string{whitelistPrefix + "Wan-Lan-v4"}) {
		t.Errorf("branch policies = %v", got)
	}
	if got := whitelistPolicyNames(t, ctrl, "lab"); !slices.Equal(got, []string{whitelistPrefix + "Lab-Web-v4"}) {
		t.Errorf("lab policies = %v", got)
	}
	if got := whitelistPolicyNames(t, ctrl, "default"); len(got) != 0 {
		t.Errorf("default policies = %v, want the whitelist removed", got)
	}
	tmls, err := ctrl.ListTrafficMatchingLists(context.Background(), "default")
	if err != nil || len(tmls) != 0 {
		t.Errorf("default lists = %+v, %v; want none", tmls, err)
	}
}

func TestSyncSharedPairsSkipSitesWithTheirOwn(t *testing.T) {
	ctrl := testutil.NewMockController()
	mgr := NewManager(ctrl, []string{"default", "branch"}, cloudflareTestProvider(t), zerolog.Nop())
	mgr.SetIPv6(false)
	pairs := []ZonePairConfig{
		{SrcName: "External", DstName: "Dmz"},
		{Site: "branch", SrcName: "Wan", DstName: "Lan"},
	}

	if err := mgr.Sync(context.Background(), pairs); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if got := whitelistPolicyNames(t, ctrl, "default"); !slices.Equal(got, []string{whitelistPrefix + "External-Dmz-v4"}) {
		t.Errorf("default policies = %v", got)
	}
	if got := whitelistPolicyNames(t, ctrl, "branch"); !slices.Equal(got, []string{whitelistPrefix + "Wan-Lan-v4"}) {
		t.Errorf("branch policies = %v", got)
	}
}

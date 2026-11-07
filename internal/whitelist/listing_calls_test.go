package whitelist

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/rs/zerolog"
)

// TestSyncListsTrafficMatchingListsOnce checks that a whitelist sync fetches
// a site's traffic matching lists once, although every list it ensures and
// the orphan sweep read them. Policies are listed once to ensure the allows,
// afresh for each pair's order check, and afresh for the sweep.
func TestSyncListsTrafficMatchingListsOnce(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "v6") {
			_, _ = w.Write([]byte("2606:4700::/32\n"))
			return
		}
		_, _ = w.Write([]byte("173.245.48.0/20\n"))
	}))
	defer srv.Close()
	provider := NewCloudflareProvider(srv.URL+"/ips-v4", srv.URL+"/ips-v6")
	provider.HTTPClient = srv.Client()

	mock := testutil.NewMockController()
	mgr := NewManager(controller.WithListingPasses(mock), []string{"test-site"}, provider, zerolog.Nop())
	pairs := []ZonePairConfig{
		{SrcName: "External", DstName: "Dmz", SrcZoneID: "zone-external", DstZoneID: "zone-dmz", DstPorts: []int{443}},
		{SrcName: "External", DstName: "Internal", SrcZoneID: "zone-external", DstZoneID: "zone-internal", DstIPs: []string{"192.0.2.10"}},
	}

	for _, pass := range []string{"first sync", "unchanged sync"} {
		mock.ResetCalls()
		if err := mgr.Sync(context.Background(), pairs); err != nil {
			t.Fatalf("%s: %v", pass, err)
		}
		tmls, policies := mock.Calls("ListTrafficMatchingLists"), mock.Calls("ListZonePolicies")
		t.Logf("%s: %d traffic matching list listings, %d policy listings", pass, tmls, policies)
		if tmls != 1 {
			t.Errorf("%s listed traffic matching lists %d times, want 1", pass, tmls)
		}
		if want := 1 + len(pairs) + 1; policies != want {
			t.Errorf("%s listed policies %d times, want %d", pass, policies, want)
		}
	}
	if got := mock.Calls("CreateZonePolicy"); got != 0 {
		t.Errorf("unchanged sync created %d policies", got)
	}
}

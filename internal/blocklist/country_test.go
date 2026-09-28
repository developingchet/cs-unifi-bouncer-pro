package blocklist

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/banstate"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/logger"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/rs/zerolog"
)

const abuseipdbBody = `#
# Aggregated Blocklist for AbuseIPDB
#
203.0.113.1      # CN  AS45090   Shenzhen Tencent
203.0.113.2      # RU  AS12389   Rostelecom
203.0.113.3      # US  AS16509   Amazon
203.0.113.4
`

func codes(cs ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(cs))
	for _, c := range cs {
		set[c] = struct{}{}
	}
	return set
}

func newFeedTestManager(feed Feed) (*Manager, *testutil.MockStore) {
	store := testutil.NewMockStore()
	claims := banstate.New(store, &mockFWManager{}, []string{"default"}, false)
	return NewFeedManager([]Feed{feed}, time.Hour, 24*time.Hour, claims, nil, false, zerolog.Nop()), store
}

func TestFetchFeed_CountryFilter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(abuseipdbBody))
	}))
	defer srv.Close()

	tests := []struct {
		name             string
		include, exclude map[string]struct{}
		want             []string
	}{
		{"no filter", nil, nil, []string{"203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"}},
		{"include", codes("CN", "RU"), nil, []string{"203.0.113.1", "203.0.113.2"}},
		{"exclude keeps untagged", nil, codes("US"), []string{"203.0.113.1", "203.0.113.2", "203.0.113.4"}},
		{"include and exclude", codes("CN", "RU"), codes("RU"), []string{"203.0.113.1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			feed := Feed{URL: srv.URL, Include: tt.include, Exclude: tt.exclude}
			mgr, store := newFeedTestManager(feed)
			if err := mgr.fetchFeed(context.Background(), feed); err != nil {
				t.Fatal(err)
			}
			bans, _ := store.BanList()
			if len(bans) != len(tt.want) {
				t.Fatalf("stored %d bans, want %d: %v", len(bans), len(tt.want), bans)
			}
			for _, ip := range tt.want {
				if _, ok := bans[ip]; !ok {
					t.Errorf("%s not banned", ip)
				}
			}
		})
	}
}

// A filter that matches nothing is a valid result, not a feed outage: the
// fetch succeeds and a pruning feed releases what it held.
func TestFetchFeed_FilterMatchingNothingPrunes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(abuseipdbBody))
	}))
	defer srv.Close()

	feed := Feed{URL: srv.URL, Include: codes("CN", "RU"), Prune: true}
	mgr, store := newFeedTestManager(feed)
	if err := mgr.fetchFeed(context.Background(), feed); err != nil {
		t.Fatal(err)
	}

	feed.Include = codes("KP")
	if err := mgr.fetchFeed(context.Background(), feed); err != nil {
		t.Fatalf("filter matching nothing reported as failure: %v", err)
	}
	if bans, _ := store.BanList(); len(bans) != 0 {
		t.Fatalf("pruning feed kept bans outside its filter: %v", bans)
	}
}

// Narrowing the filter releases the entries it now excludes, but an address
// another source also holds stays banned.
func TestFetchFeed_PruneReleasesOnlyThisSource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(abuseipdbBody))
	}))
	defer srv.Close()

	feed := Feed{URL: srv.URL, Include: codes("CN", "RU"), Prune: true}
	mgr, store := newFeedTestManager(feed)
	if err := mgr.fetchFeed(context.Background(), feed); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.claims.Claim(context.Background(), "203.0.113.2", false, "crowdsec:1", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	feed.Include = codes("CN")
	if err := mgr.fetchFeed(context.Background(), feed); err != nil {
		t.Fatal(err)
	}
	bans, _ := store.BanList()
	if _, ok := bans["203.0.113.1"]; !ok {
		t.Error("203.0.113.1 still matches the filter but was released")
	}
	entry, ok := bans["203.0.113.2"]
	if !ok {
		t.Fatal("203.0.113.2 is also held by CrowdSec but was unbanned")
	}
	if _, held := entry.Claims["blocklist:"+logger.SafeURL(srv.URL)]; held {
		t.Error("feed claim on 203.0.113.2 was not dropped")
	}
}

// The byte cap applies to the streamed body even without a Content-Length.
func TestFetchFeed_StreamedBodyOverCapRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.(http.Flusher).Flush() // chunked: no Content-Length
		_, _ = w.Write([]byte(strings.Repeat("203.0.113.9 # CN\n", 100)))
	}))
	defer srv.Close()

	feed := Feed{URL: srv.URL, Include: codes("CN"), MaxBytes: 256}
	mgr, store := newFeedTestManager(feed)
	if err := mgr.fetchFeed(context.Background(), feed); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized streamed feed = %v, want size error", err)
	}
	if bans, _ := store.BanList(); len(bans) != 0 {
		t.Fatalf("oversized feed was applied: %v", bans)
	}
}

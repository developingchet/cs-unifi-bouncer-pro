package blocklist

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// taggedBody returns n distinct public addresses, each tagged with country.
func taggedBody(start, n int, country string) string {
	var b strings.Builder
	for i := start; i < start+n; i++ {
		fmt.Fprintf(&b, "11.%d.%d.%d # %s AS64500\n", i/65536, (i/256)%256, i%256, country)
	}
	return b.String()
}

// untaggedBody is taggedBody without the country comments.
func untaggedBody(start, n int) string {
	var b strings.Builder
	for i := start; i < start+n; i++ {
		fmt.Fprintf(&b, "11.%d.%d.%d\n", i/65536, (i/256)%256, i%256)
	}
	return b.String()
}

// serveBody serves whatever body currently holds.
func serveBody(t *testing.T, body *atomic.Value) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body.Load().(string)))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestFetchFeed_FilterMatchingNothingKeepsPreviousBans(t *testing.T) {
	var body atomic.Value
	body.Store(abuseipdbBody)
	srv := serveBody(t, &body)

	feed := Feed{URL: srv.URL, Include: codes("CN", "RU"), Prune: true}
	mgr, store := newFeedTestManager(feed)
	if err := mgr.fetchFeed(context.Background(), feed); err != nil {
		t.Fatal(err)
	}

	feed.Include = codes("KP")
	err := mgr.fetchFeed(context.Background(), feed)
	if err == nil || !strings.Contains(err.Error(), "matched none") {
		t.Fatalf("err = %v, want a filter that matched nothing to be reported", err)
	}
	if bans, _ := store.BanList(); len(bans) != 2 {
		t.Fatalf("a filter matching nothing pruned the feed's bans: %v", bans)
	}
}

func TestFetchFeed_UntaggedFeedUnderIncludeFilterKeepsPreviousBans(t *testing.T) {
	var body atomic.Value
	body.Store(taggedBody(0, 20, "CN"))
	srv := serveBody(t, &body)

	feed := Feed{URL: srv.URL, Include: codes("CN"), Prune: true}
	mgr, store := newFeedTestManager(feed)
	if err := mgr.fetchFeed(context.Background(), feed); err != nil {
		t.Fatal(err)
	}

	body.Store(untaggedBody(0, 20))
	err := mgr.fetchFeed(context.Background(), feed)
	if err == nil || !strings.Contains(err.Error(), "country") {
		t.Fatalf("err = %v, want the missing country tags to be reported", err)
	}
	if bans, _ := store.BanList(); len(bans) != 20 {
		t.Fatalf("an untagged feed pruned %d of 20 bans", 20-len(bans))
	}
}

func TestFetchFeed_ShrunkFeedKeepsPreviousBans(t *testing.T) {
	var body atomic.Value
	body.Store(untaggedBody(0, 100))
	srv := serveBody(t, &body)

	feed := Feed{URL: srv.URL, Prune: true}
	mgr, store := newFeedTestManager(feed)
	if err := mgr.fetchFeed(context.Background(), feed); err != nil {
		t.Fatal(err)
	}

	body.Store(untaggedBody(0, 20))
	err := mgr.fetchFeed(context.Background(), feed)
	if !errors.Is(err, errPruningSkipped) {
		t.Fatalf("err = %v, want errPruningSkipped", err)
	}
	if bans, _ := store.BanList(); len(bans) != 100 {
		t.Fatalf("a truncated feed pruned bans: %d left of 100", len(bans))
	}

	// A modest drop is a normal refresh and prunes what the feed dropped.
	body.Store(untaggedBody(0, 70))
	if err := mgr.fetchFeed(context.Background(), feed); err != nil {
		t.Fatalf("fetch after recovery: %v", err)
	}
	if bans, _ := store.BanList(); len(bans) != 70 {
		t.Fatalf("recovered feed left %d bans, want 70", len(bans))
	}
}

func TestFetchFeed_ShrinkGuardAppliesWithoutPruningFeeds(t *testing.T) {
	var body atomic.Value
	body.Store(untaggedBody(0, 100))
	srv := serveBody(t, &body)

	feed := Feed{URL: srv.URL}
	mgr, _ := newFeedTestManager(feed)
	if err := mgr.fetchFeed(context.Background(), feed); err != nil {
		t.Fatal(err)
	}
	body.Store(untaggedBody(0, 10))
	if err := mgr.fetchFeed(context.Background(), feed); !errors.Is(err, errPruningSkipped) {
		t.Fatalf("err = %v, want errPruningSkipped", err)
	}
}

// A restarted daemon has no size from an earlier fetch, so an unfiltered
// feed is compared with the bans its previous run left behind.
func TestFetchFeed_ShrinkGuardUsesStoredBansAfterRestart(t *testing.T) {
	var body atomic.Value
	body.Store(untaggedBody(0, 100))
	srv := serveBody(t, &body)

	feed := Feed{URL: srv.URL, Prune: true}
	mgr, store := newFeedTestManager(feed)
	if err := mgr.fetchFeed(context.Background(), feed); err != nil {
		t.Fatal(err)
	}

	restarted := *mgr
	restarted.lastSize = map[string]int{}
	body.Store(untaggedBody(0, 10))
	if err := restarted.fetchFeed(context.Background(), feed); !errors.Is(err, errPruningSkipped) {
		t.Fatalf("err = %v, want errPruningSkipped", err)
	}
	if bans, _ := store.BanList(); len(bans) != 100 {
		t.Fatalf("bans after a shrunk first fetch = %d, want 100", len(bans))
	}
}

// Narrowing a country filter shrinks the kept set by design; it is not a
// truncated feed, so the feed's own size decides, not the number kept.
func TestFetchFeed_NarrowedFilterStillPrunes(t *testing.T) {
	var body atomic.Value
	body.Store(taggedBody(0, 10, "CN") + taggedBody(10, 90, "RU"))
	srv := serveBody(t, &body)

	feed := Feed{URL: srv.URL, Include: codes("CN", "RU"), Prune: true}
	mgr, store := newFeedTestManager(feed)
	if err := mgr.fetchFeed(context.Background(), feed); err != nil {
		t.Fatal(err)
	}
	feed.Include = codes("CN")
	if err := mgr.fetchFeed(context.Background(), feed); err != nil {
		t.Fatalf("narrowed filter: %v", err)
	}
	if bans, _ := store.BanList(); len(bans) != 10 {
		t.Fatalf("narrowed filter left %d bans, want 10", len(bans))
	}
}

// A feed that stays smaller for longer than the outage window is the new
// normal: the guard stops holding its old bans.
func TestFetchFeed_ShrinkAcceptedAfterOutageWindow(t *testing.T) {
	var body atomic.Value
	body.Store(untaggedBody(0, 100))
	srv := serveBody(t, &body)

	feed := Feed{URL: srv.URL, Prune: true}
	mgr, store := newFeedTestManager(feed)
	if err := mgr.fetchFeed(context.Background(), feed); err != nil {
		t.Fatal(err)
	}
	mgr.lastGood[feed.sourceKey()] = time.Now().Add(-48 * time.Hour)

	body.Store(untaggedBody(0, 20))
	if err := mgr.fetchFeed(context.Background(), feed); err != nil {
		t.Fatalf("shrink after the outage window: %v", err)
	}
	if bans, _ := store.BanList(); len(bans) != 20 {
		t.Fatalf("bans = %d, want 20", len(bans))
	}
}

func TestFetchFeed_MinPrefixSkipsBroadRanges(t *testing.T) {
	var body atomic.Value
	body.Store("198.51.100.0/24\n64.0.0.0/12\n11.1.0.0/16\n198.51.100.7\n2a0b::/40\n2a0c::/56\n")
	srv := serveBody(t, &body)

	feed := Feed{URL: srv.URL}
	mgr, store := newFeedTestManager(feed)
	mgr.SetMinPrefixes(16, 48)
	if err := mgr.fetchFeed(context.Background(), feed); err != nil {
		t.Fatal(err)
	}
	bans, _ := store.BanList()
	for _, want := range []string{"198.51.100.0/24", "11.1.0.0/16", "198.51.100.7", "2a0c::/56"} {
		if _, ok := bans[want]; !ok {
			t.Errorf("%s was not banned: %v", want, bans)
		}
	}
	for _, refused := range []string{"64.0.0.0/12", "2a0b::/40"} {
		if _, ok := bans[refused]; ok {
			t.Errorf("%s is shorter than the configured minimum but was banned", refused)
		}
	}
}

func TestSetMinPrefixes_NonPositiveValuesKeepDefaults(t *testing.T) {
	var body atomic.Value
	body.Store("64.0.0.0/7\n64.0.0.0/8\n")
	srv := serveBody(t, &body)

	feed := Feed{URL: srv.URL}
	mgr, store := newFeedTestManager(feed)
	mgr.SetMinPrefixes(0, 0)
	if err := mgr.fetchFeed(context.Background(), feed); err != nil {
		t.Fatal(err)
	}
	bans, _ := store.BanList()
	if _, ok := bans["64.0.0.0/8"]; !ok || len(bans) != 1 {
		t.Fatalf("bans = %v, want only 64.0.0.0/8", bans)
	}
}

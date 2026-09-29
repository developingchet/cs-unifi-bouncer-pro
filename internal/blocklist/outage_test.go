package blocklist

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// TestManager_FailedFetchKeepsPreviousBans: a failed fetch, or a 200 that
// lists nothing usable, extends the claims from the last good fetch, so a
// feed outage longer than two refresh intervals does not lift its bans.
func TestManager_FailedFetchKeepsPreviousBans(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{"server error", http.StatusInternalServerError, "oops"},
		{"200 with an error page", http.StatusOK, "<html><body>maintenance</body></html>"},
		{"200 empty", http.StatusOK, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var failing atomic.Bool
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if failing.Load() {
					w.WriteHeader(tt.status)
					_, _ = w.Write([]byte(tt.body))
					return
				}
				_, _ = w.Write([]byte("203.0.113.1\n203.0.113.2\n"))
			}))
			defer srv.Close()

			mgr, store, _ := newTestManager(srv.URL)
			mgr.fetchAndApply(context.Background())
			source := (Feed{URL: srv.URL}).sourceKey()
			before, _ := store.BanList()
			firstExpiry := before["203.0.113.1"].Claims[source]
			if firstExpiry.IsZero() {
				t.Fatalf("no claim recorded: %+v", before)
			}

			time.Sleep(20 * time.Millisecond)
			failing.Store(true)
			mgr.fetchAndApply(context.Background())

			after, _ := store.BanList()
			for _, ip := range []string{"203.0.113.1", "203.0.113.2"} {
				entry, ok := after[ip]
				if !ok {
					t.Fatalf("%s dropped after a failed fetch", ip)
				}
				if got := entry.Claims[source]; !got.After(firstExpiry) {
					t.Errorf("%s claim not extended: %s, was %s", ip, got, firstExpiry)
				}
			}
		})
	}
}

func TestManager_OutageCapLogDistinguishesPartialFeed(t *testing.T) {
	for _, tc := range []struct {
		name, body, wantLog, unwantedLog string
		status                           int
		wantNewBan                       bool
	}{
		{"partial response", "203.0.113.9 # CN\nstray-line\n", "feed remains incomplete after BAN_TTL", "feed failing for longer than BAN_TTL", http.StatusOK, true},
		{"failed response", "unavailable\n", "feed failing for longer than BAN_TTL", "feed remains incomplete after BAN_TTL", http.StatusServiceUnavailable, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status := http.StatusOK
			body := "203.0.113.1 # CN\n"
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte(body))
			}))
			defer srv.Close()
			feed := Feed{URL: srv.URL, SourceKind: SourceKindAbuseIPDB, Include: codes("CN"), Prune: true}
			mgr, store := newFeedTestManager(feed)
			var logs bytes.Buffer
			mgr.log = zerolog.New(&logs)
			mgr.fetchAndApply(context.Background())
			source := feed.sourceKey()
			before, _ := store.BanList()
			oldExpiry := before["203.0.113.1"].Claims[source]
			if oldExpiry.IsZero() {
				t.Fatal("initial claim missing")
			}
			logs.Reset()
			mgr.lastGood[source] = time.Now().Add(-25 * time.Hour)
			status, body = tc.status, tc.body
			mgr.fetchAndApply(context.Background())
			got := logs.String()
			if !strings.Contains(got, tc.wantLog) || strings.Contains(got, tc.unwantedLog) {
				t.Fatalf("outage log does not match response type: %s", got)
			}
			bans, _ := store.BanList()
			if !bans["203.0.113.1"].Claims[source].Equal(oldExpiry) {
				t.Fatalf("stale claim was extended past BAN_TTL: %v", bans)
			}
			if gotNewBan := !bans["203.0.113.9"].Claims[source].IsZero(); gotNewBan != tc.wantNewBan {
				t.Fatalf("new valid address claimed = %t, want %t: %v", gotNewBan, tc.wantNewBan, bans)
			}
		})
	}
}

func TestManager_FeedDownLongerThanMaxOutageStopsExtending(t *testing.T) {
	var failing atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failing.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("203.0.113.1\n"))
	}))
	defer srv.Close()

	mgr, store, _ := newTestManager(srv.URL)
	mgr.fetchAndApply(context.Background())
	source := (Feed{URL: srv.URL}).sourceKey()
	before, _ := store.BanList()
	firstExpiry := before["203.0.113.1"].Claims[source]

	mgr.lastGood[source] = time.Now().Add(-8 * 24 * time.Hour) // down past the 7-day cap
	failing.Store(true)
	mgr.fetchAndApply(context.Background())

	after, _ := store.BanList()
	if got := after["203.0.113.1"].Claims[source]; !got.Equal(firstExpiry) {
		t.Fatalf("claim extended to %s after the outage cap; want it left at %s", got, firstExpiry)
	}
}

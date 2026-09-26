package blocklist

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/logger"
)

// TestManager_FailedFetchKeepsPreviousBans covers a live finding: with the
// feed server down for two refresh intervals every feed ban lapsed. A failed
// fetch, or a 200 that lists nothing usable, now extends the claims from the
// last good fetch instead.
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
			source := "blocklist:" + logger.SafeURL(srv.URL)
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
	source := "blocklist:" + logger.SafeURL(srv.URL)
	before, _ := store.BanList()
	firstExpiry := before["203.0.113.1"].Claims[source]

	mgr.lastGood[srv.URL] = time.Now().Add(-8 * 24 * time.Hour) // down past the 7-day cap
	failing.Store(true)
	mgr.fetchAndApply(context.Background())

	after, _ := store.BanList()
	if got := after["203.0.113.1"].Claims[source]; !got.Equal(firstExpiry) {
		t.Fatalf("claim extended to %s after the outage cap; want it left at %s", got, firstExpiry)
	}
}

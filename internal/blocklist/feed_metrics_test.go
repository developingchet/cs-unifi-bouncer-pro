package blocklist

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
	promtest "github.com/prometheus/client_golang/prometheus/testutil"
)

func TestFeedMetrics(t *testing.T) {
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail.Load() {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("198.51.100.1\n198.51.100.2\n10.0.0.1\n"))
	}))
	defer srv.Close()

	mgr, _, _ := newTestManager(srv.URL)
	source := mgr.feeds[0].sourceKey()
	mgr.registerFeedMetrics()
	if got := promtest.ToFloat64(metrics.FeedFetchErrors.WithLabelValues(source)); got != 0 {
		t.Fatalf("fetch errors before any fetch = %v, want 0", got)
	}

	before := time.Now().Unix()
	mgr.fetchAndApply(context.Background())
	if got := promtest.ToFloat64(metrics.FeedEntries.WithLabelValues(source)); got != 2 {
		t.Errorf("feed_entries = %v, want 2 (the private address is skipped)", got)
	}
	success := promtest.ToFloat64(metrics.FeedLastSuccess.WithLabelValues(source))
	if success < float64(before) {
		t.Errorf("feed_last_success_timestamp_seconds = %v, want at least %d", success, before)
	}

	fail.Store(true)
	mgr.fetchAndApply(context.Background())
	if got := promtest.ToFloat64(metrics.FeedFetchErrors.WithLabelValues(source)); got != 1 {
		t.Errorf("feed_fetch_errors_total = %v, want 1", got)
	}
	if got := promtest.ToFloat64(metrics.FeedLastSuccess.WithLabelValues(source)); got != success {
		t.Errorf("a failed fetch moved feed_last_success_timestamp_seconds from %v to %v", success, got)
	}
	if got := promtest.ToFloat64(metrics.FeedEntries.WithLabelValues(source)); got != 2 {
		t.Errorf("a failed fetch changed feed_entries to %v, want 2", got)
	}
}

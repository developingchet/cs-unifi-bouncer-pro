package blocklist

import (
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
)

// registerFeedMetrics creates the error counter of each feed at zero, so a
// rate or increase alert has a series to work from before the first failure.
func (m *Manager) registerFeedMetrics() {
	for _, feed := range m.feeds {
		metrics.FeedFetchErrors.WithLabelValues(feed.sourceKey()).Add(0)
	}
}

// recordFeedEntries sets the number of entries a fetch applies.
func recordFeedEntries(feed Feed, entries int) {
	metrics.FeedEntries.WithLabelValues(feed.sourceKey()).Set(float64(entries))
}

// recordFeedOutcome counts a failed fetch, or stamps a fetch applied in full.
// A fetch applied without pruning (partial is true) is neither: its entries
// were applied, but the feed was not complete.
func recordFeedOutcome(feed Feed, err error, partial bool) {
	source := feed.sourceKey()
	switch {
	case err == nil:
		metrics.FeedLastSuccess.WithLabelValues(source).SetToCurrentTime()
	case !partial:
		metrics.FeedFetchErrors.WithLabelValues(source).Inc()
	}
}

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Feed metrics are labelled with the feed's claim source
// ("blocklist:sha256:..." or "abuseipdb:sha256:..."), never its URL, which
// often carries an access token. The daemon logs each source with the feed's
// host at startup.
var (
	// FeedEntries is how many entries the feed's last applied fetch listed.
	FeedEntries = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "feed_entries",
		Help:      "Entries the feed's last applied fetch listed, after country filtering and guards.",
	}, []string{"source"})

	// FeedLastSuccess is the Unix time of the feed's last complete fetch.
	FeedLastSuccess = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "feed_last_success_timestamp_seconds",
		Help:      "Unix timestamp of the feed's last fetch that was applied in full.",
	}, []string{"source"})

	// FeedFetchErrors counts fetches that left the feed's bans unchanged.
	FeedFetchErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "feed_fetch_errors_total",
		Help:      "Feed fetches that failed, so the bans from the last good fetch were kept.",
	}, []string{"source"})
)

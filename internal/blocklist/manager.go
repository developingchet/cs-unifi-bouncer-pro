package blocklist

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/banstate"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/decision"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/feedhttp"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/logger"
	"github.com/rs/zerolog"
)

const (
	maxFeedBytes   = 16 << 20
	maxFeedEntries = 250_000
)

// Feed is one blocklist source. Include and Exclude filter entries by the
// two-letter country code a feed puts in each line's comment
// ("192.0.2.1 # CN AS4134 ..."); entries that do not pass are dropped while
// the body is read, so they are never stored or pushed to UniFi.
type Feed struct {
	URL      string
	Include  map[string]struct{} // non-empty: keep only these countries
	Exclude  map[string]struct{} // never keep these countries
	MaxBytes int64               // download cap; 0 means maxFeedBytes
	// Prune releases this feed's bans that a successful fetch no longer
	// lists, instead of letting them lapse after two refresh intervals. A
	// narrowed country filter then shrinks UniFi on the first fetch.
	Prune bool
}

// PlainFeeds wraps URLs as unfiltered feeds.
func PlainFeeds(urls []string) []Feed {
	feeds := make([]Feed, len(urls))
	for i, url := range urls {
		feeds[i] = Feed{URL: url}
	}
	return feeds
}

func (f Feed) filtered() bool { return len(f.Include) > 0 || len(f.Exclude) > 0 }

// allows reports whether an entry tagged with country passes the filter.
// An untagged entry passes only when no include list is set.
func (f Feed) allows(country string) bool {
	if len(f.Include) > 0 {
		if _, ok := f.Include[country]; !ok {
			return false
		}
	}
	_, excluded := f.Exclude[country]
	return !excluded
}

func (f Feed) maxBytes() int64 {
	if f.MaxBytes > 0 {
		return f.MaxBytes
	}
	return maxFeedBytes
}

type Manager struct {
	feeds     []Feed
	interval  time.Duration
	claims    *banstate.Manager
	protected []*net.IPNet
	dryRun    bool
	log       zerolog.Logger
	client    *http.Client

	// maxOutage bounds how long a failing feed keeps its bans, measured from
	// its last good fetch (or from startup). lastGood is only touched by Run.
	maxOutage time.Duration
	lastGood  map[string]time.Time
}

// NewManager builds a manager for unfiltered feed URLs. maxOutage is how
// long an unreachable feed keeps the bans from its last good fetch; the
// daemon passes BAN_TTL.
func NewManager(urls []string, interval, maxOutage time.Duration, claims *banstate.Manager,
	protected []*net.IPNet, dryRun bool, log zerolog.Logger,
) *Manager {
	return NewFeedManager(PlainFeeds(urls), interval, maxOutage, claims, protected, dryRun, log)
}

// NewFeedManager builds a manager for feeds that may carry country filters.
func NewFeedManager(feeds []Feed, interval, maxOutage time.Duration, claims *banstate.Manager,
	protected []*net.IPNet, dryRun bool, log zerolog.Logger,
) *Manager {
	lastGood := make(map[string]time.Time, len(feeds))
	now := time.Now()
	// The client timeout covers reading the body, so a feed allowed to be
	// larger than the default gets longer to download.
	timeout := 30 * time.Second
	for _, feed := range feeds {
		lastGood[feed.URL] = now
		if feed.maxBytes() > maxFeedBytes {
			timeout = 2 * time.Minute
		}
	}
	return &Manager{
		feeds: feeds, interval: interval, claims: claims,
		protected: protected, dryRun: dryRun, log: log,
		client:    &http.Client{Timeout: timeout, CheckRedirect: feedhttp.CheckRedirect},
		maxOutage: maxOutage, lastGood: lastGood,
	}
}

func (m *Manager) Run(ctx context.Context) {
	m.fetchAndApply(ctx)
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.fetchAndApply(ctx)
		}
	}
}

func (m *Manager) fetchAndApply(ctx context.Context) {
	for _, feed := range m.feeds {
		url := feed.URL
		if err := m.fetchFeed(ctx, feed); err != nil {
			m.log.Error().Err(err).Str("url", logger.SafeURL(url)).Msg("blocklist: fetch failed")
			m.keepClaims(url)
			continue
		}
		m.lastGood[url] = time.Now()
	}
}

// keepClaims extends the bans from url's last successful fetch through
// another two refresh intervals. A feed's bans lapse when a successful fetch
// no longer lists them, not because the feed was unreachable: otherwise one
// failed fetch let the whole list expire at the moment the next fetch was
// due, and a longer outage unbanned all of it. A feed that has failed for
// longer than maxOutage is treated as gone and its bans run out.
func (m *Manager) keepClaims(url string) {
	if m.dryRun {
		return
	}
	display := logger.SafeURL(url)
	down := time.Since(m.lastGood[url])
	if m.maxOutage > 0 && down >= m.maxOutage {
		m.log.Error().Str("url", display).Stringer("unreachable_for", down.Round(time.Minute)).
			Msg("blocklist: feed failing for longer than BAN_TTL; its bans are no longer extended and will expire")
		return
	}
	n, err := m.claims.ExtendSource("blocklist:"+display, time.Now().Add(m.interval*2))
	if err != nil {
		m.log.Error().Err(err).Str("url", display).Msg("blocklist: could not extend bans from the last successful fetch")
		return
	}
	if n > 0 {
		m.log.Warn().Str("url", display).Int("bans", n).Msg("blocklist: keeping bans from the last successful fetch")
	}
}

// fetchFeed downloads one feed and claims its addresses. Feed URLs often
// carry an access token, so logs and claim sources use the redacted form.
// The body is read line by line and filtered as it arrives, so a large
// country-filtered list costs memory only for the entries it keeps.
func (m *Manager) fetchFeed(ctx context.Context, feed Feed) error {
	url := feed.URL
	display := logger.SafeURL(url)
	limit := feed.maxBytes()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", logger.SafeURLError(err, display))
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch: %w", logger.SafeURLError(err, display))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	if resp.ContentLength > limit {
		return fmt.Errorf("blocklist exceeds %d bytes", limit)
	}
	body := &countingReader{r: io.LimitReader(resp.Body, limit+1)}

	var entries []banstate.ClaimRequest
	seen := make(map[string]struct{})
	var skipped, filtered int
	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		raw := scanner.Text()
		line := feedLineValue(raw)
		if line == "" {
			continue
		}
		if feed.filtered() && !feed.allows(feedLineCountry(raw)) {
			filtered++
			continue
		}
		ip, ipv6, ok := parseEntry(line)
		if !ok || decision.Unbannable(ip, ipv6, m.protected) {
			skipped++
			continue
		}
		if _, duplicate := seen[ip]; duplicate {
			continue
		}
		if len(entries) >= maxFeedEntries {
			return fmt.Errorf("blocklist exceeds %d unique entries", maxFeedEntries)
		}
		seen[ip] = struct{}{}
		entries = append(entries, banstate.ClaimRequest{IP: ip, IPv6: ipv6})
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan blocklist: %w", err)
	}
	if body.n > limit {
		return fmt.Errorf("blocklist exceeds %d bytes", limit)
	}
	if len(entries) == 0 && filtered == 0 {
		// An error page or truncated response served with 200 must not
		// count as "the feed now lists nothing".
		return fmt.Errorf("no valid entries (%d lines skipped)", skipped)
	}
	if len(entries) == 0 {
		// The feed is fine; the country filter matched nothing in it.
		m.log.Warn().Str("url", display).Int("filtered", filtered).
			Msg("blocklist: country filter matched no entries in this feed")
	}
	if m.dryRun {
		m.log.Info().Str("url", display).Int("entries", len(entries)).Int("filtered", filtered).
			Msg("[DRY-RUN] would import blocklist")
		return nil
	}
	source := "blocklist:" + display
	added := 0
	if len(entries) > 0 {
		expiresAt := time.Now().Add(m.interval * 2)
		added, err = m.claims.ClaimMany(ctx, entries, source, expiresAt)
		if err != nil {
			m.log.Warn().Err(err).Str("url", display).Msg("blocklist: some bans could not be applied yet; reconcile will retry")
		}
	}
	removed := 0
	if feed.Prune {
		removed, err = m.claims.ReleaseSourceExcept(ctx, source, seen)
		if err != nil {
			m.log.Warn().Err(err).Str("url", display).Msg("blocklist: could not release bans the feed no longer lists")
		}
	}
	event := m.log.Info().Str("url", display).Int("entries", len(entries)).Int("new", added).
		Int("skipped", skipped)
	if feed.filtered() {
		event = event.Int("filtered", filtered)
	}
	if feed.Prune {
		event = event.Int("removed", removed)
	}
	event.Msg("blocklist: fetch complete")
	return nil
}

// countingReader counts the bytes read through it, so a body longer than
// the feed's cap is rejected instead of silently truncated.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// feedLineCountry returns the two-letter country code a feed puts first in
// a line's "#" comment ("192.0.2.1  # CN  AS4134 ..."), upper-cased, or ""
// when the line carries none.
func feedLineCountry(line string) string {
	i := strings.IndexByte(line, '#')
	if i < 0 {
		return ""
	}
	fields := strings.Fields(line[i+1:])
	if len(fields) == 0 || len(fields[0]) != 2 {
		return ""
	}
	code := strings.ToUpper(fields[0])
	if code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
		return ""
	}
	return code
}

// feedLineValue returns the address field of a feed line: the text before
// any "#" or ";" comment, up to the first whitespace. Common feeds annotate
// entries inline (Spamhaus DROP: "192.0.2.0/24 ; SBL123"), and those lines
// used to be skipped as unparseable. "" means the line holds no entry.
func feedLineValue(line string) string {
	if i := strings.IndexAny(line, "#;"); i >= 0 {
		line = line[:i]
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// parseEntry canonicalises one feed line the same way CrowdSec decisions are,
// so a host prefix like 203.0.113.9/32 is stored as the bare address.
func parseEntry(s string) (ip string, ipv6 bool, ok bool) {
	canonical, _, err := decision.ParseAndSanitize(s)
	if err != nil {
		return "", false, false
	}
	return canonical, decision.IsIPv6(canonical), true
}

package blocklist

import (
	"bufio"
	"fmt"
	"io"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/banstate"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/decision"
)

const (
	// shrinkGuardMinPrevious is the smallest previous feed size the shrink
	// guard applies to. A short list can legitimately halve between fetches.
	shrinkGuardMinPrevious = 50
	// shrinkGuardDivisor makes a fetch with fewer than 1/divisor of the
	// previous entries count as a shrink. 2 means below half.
	shrinkGuardDivisor = 2
)

// feedScan is the outcome of reading one feed body.
type feedScan struct {
	entries []banstate.ClaimRequest
	seen    map[string]struct{}
	// valid counts the entries that parsed, before country filtering and
	// the protection checks; it measures the feed itself.
	valid    int
	skipped  int
	filtered int
	// untagged counts the filtered entries that carried no country code.
	untagged int
	invalid  int
}

// scanFeed reads a feed line by line and keeps the entries that pass the
// country filter and the range guards. The body is filtered as it arrives, so
// a large country-filtered list costs memory only for the entries it keeps.
func (m *Manager) scanFeed(body io.Reader, feed Feed) (feedScan, error) {
	scan := feedScan{seen: make(map[string]struct{})}
	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		raw := scanner.Text()
		line := feedLineValue(raw)
		if line == "" {
			continue
		}
		ip, ipv6, ok := parseEntry(line)
		if !ok {
			scan.skipped++
			scan.invalid++
			continue
		}
		scan.valid++
		if country := feedLineCountry(raw); feed.filtered() && !feed.allows(country) {
			scan.filtered++
			if country == "" {
				scan.untagged++
			}
			continue
		}
		if m.unbannable(ip, ipv6) {
			scan.skipped++
			continue
		}
		if _, duplicate := scan.seen[ip]; duplicate {
			continue
		}
		if len(scan.entries) >= maxFeedEntries {
			return scan, fmt.Errorf("blocklist exceeds %d unique entries", maxFeedEntries)
		}
		scan.seen[ip] = struct{}{}
		scan.entries = append(scan.entries, banstate.ClaimRequest{IP: ip, IPv6: ipv6})
	}
	if err := scanner.Err(); err != nil {
		return scan, fmt.Errorf("scan blocklist: %w", err)
	}
	return scan, nil
}

// unbannable reports whether a feed entry must be skipped: private,
// whitelisted, or a range shorter than the configured minimum prefix.
func (m *Manager) unbannable(ip string, ipv6 bool) bool {
	return decision.Unbannable(ip, ipv6, m.protected) ||
		decision.TooBroadFor(ip, ipv6, m.minPrefixV4, m.minPrefixV6)
}

// noMatchError describes a feed whose entries were all rejected by the
// country filter.
func noMatchError(feed Feed, scan feedScan) error {
	if len(feed.Include) > 0 && scan.untagged == scan.filtered {
		return fmt.Errorf("country filter cannot apply: none of the %d entries carries a country code, so the feed format may have changed; previous bans kept", scan.filtered)
	}
	return fmt.Errorf("country filter matched none of the %d entries; previous bans kept", scan.filtered)
}

// previousSize returns how many entries the feed listed when it was last
// applied in full. After a restart there is no such record, so an unfiltered
// feed falls back to the bans it left behind; a filtered feed has none, as
// its bans only count the entries the filter kept.
func (m *Manager) previousSize(feed Feed) int {
	source := feed.sourceKey()
	if n, ok := m.lastSize[source]; ok {
		return n
	}
	if feed.filtered() {
		return 0
	}
	n, err := m.claims.CountSource(source)
	if err != nil {
		m.log.Warn().Err(err).Msg("blocklist: could not count the feed's existing bans")
		return 0
	}
	return n
}

// shrunk reports whether a feed that listed previous entries now lists fewer
// than half as many. That pattern is a truncated download or a format change
// far more often than a real cleanup, and pruning on it would unban most of
// the list at once. A feed that stays small past the outage window is taken
// as the new normal: its old bans would have expired by then anyway.
func (m *Manager) shrunk(source string, previous, current int) bool {
	if previous < shrinkGuardMinPrevious || current*shrinkGuardDivisor >= previous {
		return false
	}
	return m.maxOutage <= 0 || time.Since(m.lastGood[source]) < m.maxOutage
}

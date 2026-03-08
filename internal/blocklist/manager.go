package blocklist

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/firewall"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/rs/zerolog"
)

// Manager periodically fetches plain-text IP/CIDR blocklists from configured
// URLs and applies them through the firewall.Manager ban path.
type Manager struct {
	urls     []string
	interval time.Duration
	fwMgr    firewall.Manager
	store    storage.Store
	sites    []string
	prefix   string
	log      zerolog.Logger
	client   *http.Client
}

// NewManager creates a blocklist Manager.
func NewManager(urls []string, interval time.Duration, prefix string,
	fwMgr firewall.Manager, store storage.Store, sites []string, log zerolog.Logger,
) *Manager {
	return &Manager{
		urls:     urls,
		interval: interval,
		prefix:   prefix,
		fwMgr:    fwMgr,
		store:    store,
		sites:    sites,
		log:      log,
		client:   &http.Client{Timeout: 30 * time.Second},
	}
}

// Run fetches all blocklists on startup and then on every interval tick until ctx is cancelled.
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

// fetchAndApply downloads each configured URL and bans all valid IPs/CIDRs found.
func (m *Manager) fetchAndApply(ctx context.Context) {
	for _, url := range m.urls {
		if err := m.fetchURL(ctx, url); err != nil {
			m.log.Error().Err(err).Str("url", url).Msg("blocklist: fetch failed")
		}
	}
}

func (m *Manager) fetchURL(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}

	// Bans from external blocklists expire after 2x the refresh interval so they are
	// refreshed each cycle and naturally expire if the URL becomes unreachable.
	expiresAt := time.Now().Add(m.interval * 2)

	var applied, skipped int
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		ip, ipv6, ok := parseEntry(line)
		if !ok {
			skipped++
			continue
		}

		if err := m.store.BanRecord(ip, expiresAt, ipv6); err != nil {
			m.log.Warn().Err(err).Str("ip", ip).Msg("blocklist: failed to record ban in bbolt")
			continue
		}
		for _, site := range m.sites {
			if err := m.fwMgr.ApplyBan(ctx, site, ip, ipv6); err != nil {
				m.log.Warn().Err(err).Str("ip", ip).Str("site", site).Msg("blocklist: ApplyBan failed")
			}
		}
		applied++
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	m.log.Info().Str("url", url).Int("applied", applied).Int("skipped", skipped).
		Msg("blocklist: fetch complete")
	return nil
}

// parseEntry validates and normalises an IP or CIDR string.
// Returns the canonical form, whether it is IPv6, and whether it is valid.
func parseEntry(s string) (ip string, ipv6 bool, ok bool) {
	// Try CIDR first
	if _, network, err := net.ParseCIDR(s); err == nil {
		is6 := network.IP.To4() == nil
		return network.String(), is6, true
	}
	// Then bare IP
	parsed := net.ParseIP(s)
	if parsed == nil {
		return "", false, false
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.String(), false, true
	}
	return parsed.String(), true, true
}

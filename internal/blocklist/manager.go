package blocklist

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/banstate"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/decision"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/firewall"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/rs/zerolog"
)

const (
	maxFeedBytes   = 16 << 20
	maxFeedEntries = 250_000
)

type Manager struct {
	urls      []string
	interval  time.Duration
	claims    *banstate.Manager
	protected []*net.IPNet
	dryRun    bool
	log       zerolog.Logger
	client    *http.Client
}

func NewManager(urls []string, interval time.Duration,
	fwMgr firewall.Manager, store storage.Store, sites []string,
	protected []*net.IPNet, shared *banstate.Manager, dryRun bool, log zerolog.Logger,
) *Manager {
	if shared == nil {
		shared = banstate.New(store, fwMgr, sites, dryRun)
	}
	return &Manager{
		urls: urls, interval: interval, claims: shared,
		protected: protected, dryRun: dryRun, log: log,
		client: &http.Client{Timeout: 30 * time.Second},
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
	if resp.ContentLength > maxFeedBytes {
		return fmt.Errorf("blocklist exceeds %d bytes", maxFeedBytes)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes+1))
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	if len(body) > maxFeedBytes {
		return fmt.Errorf("blocklist exceeds %d bytes", maxFeedBytes)
	}

	type address struct {
		ip   string
		ipv6 bool
	}
	var entries []address
	seen := make(map[string]struct{})
	var skipped int
	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ip, ipv6, ok := parseEntry(line)
		if !ok || decision.IsPrivate(ip) || decision.IsWhitelisted(ip, m.protected) {
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
		entries = append(entries, address{ip: ip, ipv6: ipv6})
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan blocklist: %w", err)
	}
	if m.dryRun {
		m.log.Info().Str("url", url).Int("entries", len(entries)).Msg("[DRY-RUN] would import blocklist")
		return nil
	}
	expiresAt := time.Now().Add(m.interval * 2)
	var applied int
	for _, entry := range entries {
		if _, err := m.claims.Claim(ctx, entry.ip, entry.ipv6, "blocklist:"+url, expiresAt); err != nil {
			m.log.Warn().Err(err).Str("ip", entry.ip).Msg("blocklist: failed to apply ban")
			continue
		}
		applied++
	}
	m.log.Info().Str("url", url).Int("applied", applied).Int("skipped", skipped).Msg("blocklist: fetch complete")
	return nil
}

func parseEntry(s string) (ip string, ipv6 bool, ok bool) {
	if _, network, err := net.ParseCIDR(s); err == nil {
		return network.String(), network.IP.To4() == nil, true
	}
	parsed := net.ParseIP(s)
	if parsed == nil {
		return "", false, false
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.String(), false, true
	}
	return parsed.String(), true, true
}

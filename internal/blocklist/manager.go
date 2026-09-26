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
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/feedhttp"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/logger"
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

func NewManager(urls []string, interval time.Duration, claims *banstate.Manager,
	protected []*net.IPNet, dryRun bool, log zerolog.Logger,
) *Manager {
	return &Manager{
		urls: urls, interval: interval, claims: claims,
		protected: protected, dryRun: dryRun, log: log,
		client: &http.Client{Timeout: 30 * time.Second, CheckRedirect: feedhttp.CheckRedirect},
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
			m.log.Error().Err(err).Str("url", logger.SafeURL(url)).Msg("blocklist: fetch failed")
		}
	}
}

// fetchURL downloads one feed and claims its addresses. Feed URLs often carry
// an access token, so logs and claim sources use the redacted form.
func (m *Manager) fetchURL(ctx context.Context, url string) error {
	display := logger.SafeURL(url)
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

	var entries []banstate.ClaimRequest
	seen := make(map[string]struct{})
	var skipped int
	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ip, ipv6, ok := parseEntry(line)
		if !ok || decision.TooBroad(ip, ipv6) || decision.IsPrivate(ip) || decision.IsWhitelisted(ip, m.protected) {
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
	if m.dryRun {
		m.log.Info().Str("url", display).Int("entries", len(entries)).Msg("[DRY-RUN] would import blocklist")
		return nil
	}
	expiresAt := time.Now().Add(m.interval * 2)
	added, err := m.claims.ClaimMany(ctx, entries, "blocklist:"+display, expiresAt)
	if err != nil {
		m.log.Warn().Err(err).Str("url", display).Msg("blocklist: some bans could not be applied yet; reconcile will retry")
	}
	m.log.Info().Str("url", display).Int("entries", len(entries)).Int("new", added).
		Int("skipped", skipped).Msg("blocklist: fetch complete")
	return nil
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

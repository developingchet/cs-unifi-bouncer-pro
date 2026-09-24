package banstate

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/firewall"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
)

// Manager serializes changes to ban ownership and their firewall transitions.
type Manager struct {
	mu     sync.Mutex
	store  storage.Store
	fw     firewall.Manager
	sites  []string
	dryRun bool
}

func New(store storage.Store, fw firewall.Manager, sites []string, dryRun bool) *Manager {
	return &Manager{store: store, fw: fw, sites: sites, dryRun: dryRun}
}

func claimsFor(entry storage.BanEntry) map[string]time.Time {
	if entry.Claims == nil {
		return map[string]time.Time{"legacy": entry.ExpiresAt}
	}
	claims := make(map[string]time.Time, len(entry.Claims))
	for source, expiry := range entry.Claims {
		claims[source] = expiry
	}
	return claims
}

func active(claims map[string]time.Time, now time.Time) bool {
	for _, expiry := range claims {
		if expiry.IsZero() || expiry.After(now) {
			return true
		}
	}
	return false
}

func latestExpiry(claims map[string]time.Time) time.Time {
	var latest time.Time
	for _, expiry := range claims {
		if expiry.IsZero() {
			return time.Time{}
		}
		if expiry.After(latest) {
			latest = expiry
		}
	}
	return latest
}

func (m *Manager) Claim(ctx context.Context, ip string, ipv6 bool, source string, expiry time.Time) (bool, error) {
	if source == "" {
		return false, fmt.Errorf("ban source is required")
	}
	if m.dryRun {
		return false, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, err := m.store.BanGet(ip)
	if err != nil {
		return false, fmt.Errorf("read ban: %w", err)
	}
	now := time.Now().UTC()
	wasActive := false
	if entry == nil {
		entry = &storage.BanEntry{RecordedAt: now, IPv6: ipv6, Claims: make(map[string]time.Time)}
	} else {
		entry.Claims = claimsFor(*entry)
		wasActive = active(entry.Claims, now)
	}
	entry.Claims[source] = expiry.UTC()
	entry.ExpiresAt = latestExpiry(entry.Claims)
	entry.Pending = entry.Pending || !wasActive
	if err := m.store.BanPut(ip, *entry); err != nil {
		return false, fmt.Errorf("record ban: %w", err)
	}
	if !entry.Pending {
		return false, nil
	}
	if err := m.apply(ctx, ip, ipv6, true); err != nil {
		return false, err
	}
	entry.Pending = false
	if err := m.store.BanPut(ip, *entry); err != nil {
		return false, fmt.Errorf("confirm ban: %w", err)
	}
	return !wasActive, nil
}

func (m *Manager) Release(ctx context.Context, ip, source string) (bool, error) {
	if source == "" {
		return false, fmt.Errorf("ban source is required")
	}
	if m.dryRun {
		return false, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, err := m.store.BanGet(ip)
	if err != nil || entry == nil {
		return false, err
	}
	claims := claimsFor(*entry)
	_, found := claims[source]
	_, legacy := claims["legacy"]
	legacyDecision := legacy && strings.HasPrefix(source, "crowdsec:")
	if !found && !legacyDecision {
		return false, nil
	}
	delete(claims, source)
	if legacyDecision {
		delete(claims, "legacy")
	}
	if active(claims, time.Now().UTC()) {
		entry.Claims = claims
		entry.ExpiresAt = latestExpiry(claims)
		return false, m.store.BanPut(ip, *entry)
	}
	if err := m.apply(ctx, ip, entry.IPv6, false); err != nil {
		return false, err
	}
	if err := m.store.BanDelete(ip); err != nil {
		return false, fmt.Errorf("delete ban: %w", err)
	}
	return true, nil
}

// ReleaseAll removes every claim for an explicit manual unban.
func (m *Manager) ReleaseAll(ctx context.Context, ip string, ipv6 bool) (bool, error) {
	if m.dryRun {
		return false, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, err := m.store.BanGet(ip)
	if err != nil {
		return false, err
	}
	if entry == nil {
		return false, m.apply(ctx, ip, ipv6, false)
	}
	if err := m.apply(ctx, ip, entry.IPv6, false); err != nil {
		return false, err
	}
	if err := m.store.BanDelete(ip); err != nil {
		return false, fmt.Errorf("delete ban: %w", err)
	}
	return true, nil
}

func (m *Manager) Expire(ctx context.Context, ip string) (bool, error) {
	if m.dryRun {
		return false, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, err := m.store.BanGet(ip)
	if err != nil || entry == nil {
		return false, err
	}
	now := time.Now().UTC()
	claims := claimsFor(*entry)
	changed := false
	for source, expiry := range claims {
		if !expiry.IsZero() && !expiry.After(now) {
			delete(claims, source)
			changed = true
		}
	}
	if !changed {
		return false, nil
	}
	if len(claims) > 0 {
		entry.Claims = claims
		entry.ExpiresAt = latestExpiry(claims)
		return false, m.store.BanPut(ip, *entry)
	}
	if err := m.apply(ctx, ip, entry.IPv6, false); err != nil {
		return false, err
	}
	if err := m.store.BanDelete(ip); err != nil {
		return false, fmt.Errorf("delete expired ban: %w", err)
	}
	return true, nil
}

func (m *Manager) apply(ctx context.Context, ip string, ipv6, ban bool) error {
	var siteErrors []error
	for _, site := range m.sites {
		var err error
		if ban {
			err = m.fw.ApplyBan(ctx, site, ip, ipv6)
		} else {
			err = m.fw.ApplyUnban(ctx, site, ip, ipv6)
		}
		if err != nil {
			var unauthorized *controller.ErrUnauthorized
			var rateLimit *controller.ErrRateLimit
			if errors.As(err, &unauthorized) || errors.As(err, &rateLimit) {
				return fmt.Errorf("site %s: %w", site, err)
			}
			siteErrors = append(siteErrors, fmt.Errorf("site %s: %w", site, err))
		}
	}
	return errors.Join(siteErrors...)
}

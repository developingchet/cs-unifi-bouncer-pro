package banstate

import (
	"context"
	"fmt"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
)

// ExtendSource moves every unexpired claim held by source to expiry when
// that is later. It changes no firewall state: the addresses are already
// banned. It returns how many claims were extended. A feed whose fetch fails
// uses it to keep its bans until a fetch succeeds, instead of letting the
// whole list lapse during an outage.
func (m *Manager) ExtendSource(source string, expiry time.Time) (int, error) {
	if source == "" {
		return 0, fmt.Errorf("ban source is required")
	}
	if m.dryRun {
		return 0, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	bans, err := m.store.BanList()
	if err != nil {
		return 0, fmt.Errorf("list bans: %w", err)
	}
	now := time.Now().UTC()
	expiry = expiry.UTC()
	updates := make(map[string]storage.BanEntry)
	for ip, entry := range bans {
		current, ok := entry.Claims[source]
		if !ok || current.IsZero() || !current.After(now) || !expiry.After(current) {
			continue
		}
		claims := claimsFor(entry)
		claims[source] = expiry
		updated := entry
		updated.Claims = claims
		updated.ExpiresAt = latestExpiry(claims)
		updates[ip] = updated
	}
	if len(updates) == 0 {
		return 0, nil
	}
	if err := m.store.BanPutMany(updates); err != nil {
		return 0, fmt.Errorf("extend %s claims: %w", source, err)
	}
	return len(updates), nil
}

// CountSource returns how many unexpired claims source holds. A feed uses it
// to compare a fresh fetch with what the previous one left behind.
func (m *Manager) CountSource(source string) (int, error) {
	if source == "" {
		return 0, fmt.Errorf("ban source is required")
	}
	m.mu.Lock()
	bans, err := m.store.BanList()
	m.mu.Unlock()
	if err != nil {
		return 0, fmt.Errorf("list bans: %w", err)
	}
	now := time.Now().UTC()
	count := 0
	for _, entry := range bans {
		if expiry, ok := entry.Claims[source]; ok && (expiry.IsZero() || expiry.After(now)) {
			count++
		}
	}
	return count, nil
}

// ReleaseSourceExcept drops source's claim from every ban whose address is
// not in keep, unbanning addresses no other source still holds. A filtered
// feed uses it after a successful fetch so entries it stopped listing, or
// that a narrowed filter now excludes, leave UniFi at the next sync instead
// of two refresh intervals later. It returns how many addresses were
// unbanned.
func (m *Manager) ReleaseSourceExcept(ctx context.Context, source string, keep map[string]struct{}) (int, error) {
	if source == "" {
		return 0, fmt.Errorf("ban source is required")
	}
	if m.dryRun {
		return 0, nil
	}
	m.mu.Lock()
	bans, err := m.store.BanList()
	m.mu.Unlock()
	if err != nil {
		return 0, fmt.Errorf("list bans: %w", err)
	}
	var stale []string
	for ip, entry := range bans {
		if _, held := entry.Claims[source]; !held {
			continue
		}
		if _, listed := keep[ip]; !listed {
			stale = append(stale, ip)
		}
	}
	removed := 0
	for _, ip := range stale {
		if err := ctx.Err(); err != nil {
			return removed, err
		}
		unbanned, err := m.Release(ctx, ip, source)
		if err != nil {
			return removed, fmt.Errorf("release %s: %w", ip, err)
		}
		if unbanned {
			removed++
		}
	}
	return removed, nil
}

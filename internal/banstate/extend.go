package banstate

import (
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

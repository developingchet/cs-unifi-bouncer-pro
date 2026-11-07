package banstate

import (
	"fmt"
	"strings"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
)

// LegacyClaim is the claim source of bans stored by 1.x, which recorded
// neither claims nor the decision behind a ban.
const LegacyClaim = "legacy"

// ClaimLegacyBans gives every ban stored without claims a LegacyClaim that
// ends with the ban. It returns how many bans it changed. Run it before
// anything else reads the ban database: elsewhere a ban without claims holds
// no active claim.
func ClaimLegacyBans(store storage.Store) (int, error) {
	bans, err := store.BanList()
	if err != nil {
		return 0, fmt.Errorf("list bans: %w", err)
	}
	updates := make(map[string]storage.BanEntry)
	for ip, entry := range bans {
		if len(entry.Claims) > 0 {
			continue
		}
		entry.Claims = map[string]time.Time{LegacyClaim: entry.ExpiresAt}
		updates[ip] = entry
	}
	if err := store.BanPutMany(updates); err != nil {
		return 0, fmt.Errorf("write legacy claims: %w", err)
	}
	return len(updates), nil
}

// RetireLegacyClaims drops the LegacyClaim of every ban that a CrowdSec
// decision also claims, so deleting that decision lifts the ban. Run it once
// the first LAPI batch has claimed every active decision. A 1.x ban that no
// decision claims then keeps its legacy claim until the claim expires. It
// returns how many claims it dropped.
func (m *Manager) RetireLegacyClaims() (int, error) {
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
	updates := make(map[string]storage.BanEntry)
	for ip, entry := range bans {
		if _, legacy := entry.Claims[LegacyClaim]; !legacy || !hasDecisionClaim(entry.Claims, now) {
			continue
		}
		claims := claimsFor(entry)
		delete(claims, LegacyClaim)
		entry.Claims = claims
		entry.ExpiresAt = latestExpiry(claims)
		updates[ip] = entry
	}
	if err := m.store.BanPutMany(updates); err != nil {
		return 0, fmt.Errorf("drop legacy claims: %w", err)
	}
	return len(updates), nil
}

// hasDecisionClaim reports whether a CrowdSec decision holds an active claim.
func hasDecisionClaim(claims map[string]time.Time, now time.Time) bool {
	for source, expiry := range claims {
		if strings.HasPrefix(source, "crowdsec:") && (expiry.IsZero() || expiry.After(now)) {
			return true
		}
	}
	return false
}

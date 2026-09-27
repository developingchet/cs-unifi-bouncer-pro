package banstate

import (
	"fmt"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/decision"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
)

// CanonicalizeHostPrefixes rekeys bans stored as a single-host prefix
// (203.0.113.9/32, 2001:db8::1/128) under the bare address. Earlier versions
// stored them that way; UniFi rejects host prefixes in firewall groups, so
// such a ban was never enforced and made its shard fail on every flush.
// Claims for the same address are merged, keeping each source's later
// expiry. It returns the number of entries rekeyed. Run before the firewall
// manager loads the ban database.
func CanonicalizeHostPrefixes(store storage.Store) (int, error) {
	bans, err := store.BanList()
	if err != nil {
		return 0, fmt.Errorf("list bans: %w", err)
	}
	merged := make(map[string]storage.BanEntry)
	var stale []string
	for key, entry := range bans {
		addr, ok := decision.HostPrefixAddress(key)
		if !ok {
			continue
		}
		stale = append(stale, key)
		target, seen := merged[addr]
		if !seen {
			if existing, exists := bans[addr]; exists {
				target, seen = existing, true
			}
		}
		if seen {
			merged[addr] = mergeEntries(target, entry)
		} else {
			entry.Claims = claimsFor(entry)
			merged[addr] = entry
		}
	}
	if len(stale) == 0 {
		return 0, nil
	}
	if err := store.BanPutMany(merged); err != nil {
		return 0, fmt.Errorf("write canonical bans: %w", err)
	}
	for _, key := range stale {
		if err := store.BanDelete(key); err != nil {
			return 0, fmt.Errorf("delete host-prefix ban %s: %w", key, err)
		}
	}
	return len(stale), nil
}

// mergeEntries combines two records for one address: every claim survives
// with the later of its expiries, the ban stays pending if either was, and
// the earlier RecordedAt is kept.
func mergeEntries(a, b storage.BanEntry) storage.BanEntry {
	claims := claimsFor(a)
	for source, expiry := range claimsFor(b) {
		current, ok := claims[source]
		if !ok || expiry.IsZero() || (!current.IsZero() && expiry.After(current)) {
			claims[source] = expiry
		}
	}
	out := a
	out.Claims = claims
	out.ExpiresAt = latestExpiry(claims)
	out.Pending = a.Pending || b.Pending
	out.IPv6 = a.IPv6 || b.IPv6
	if !b.RecordedAt.IsZero() && (out.RecordedAt.IsZero() || b.RecordedAt.Before(out.RecordedAt)) {
		out.RecordedAt = b.RecordedAt
	}
	return out
}

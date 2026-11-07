package testutil

import (
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
)

// BanSource is the claim source of the bans PutBan stores.
const BanSource = "test"

// PutBan stores a confirmed ban on ip held by a single BanSource claim that
// ends at expiresAt (zero for no expiry).
func PutBan(store storage.Store, ip string, expiresAt time.Time, ipv6 bool) error {
	expiry := expiresAt.UTC()
	return store.BanPut(ip, storage.BanEntry{
		RecordedAt: time.Now().UTC(),
		ExpiresAt:  expiry,
		IPv6:       ipv6,
		Claims:     map[string]time.Time{BanSource: expiry},
	})
}

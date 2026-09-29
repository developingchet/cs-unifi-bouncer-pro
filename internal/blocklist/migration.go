package blocklist

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/logger"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
)

// MigrateLegacySources removes URL-bearing claim keys before feed workers run.
// The old key discarded query strings and importer identity, so several current
// feeds can match it. Only an unambiguous owner receives the claim. Ambiguous
// or unconfigured claims keep their original expiry under an opaque key until
// a successful refresh establishes ownership; assigning them to every matching
// feed could leave an unrelated ban extended indefinitely.
func MigrateLegacySources(store storage.Store, feeds []Feed) error {
	owners := make(map[string]map[string]struct{}, len(feeds))
	for _, feed := range feeds {
		legacy := "blocklist:" + logger.SafeURL(feed.URL)
		if owners[legacy] == nil {
			owners[legacy] = make(map[string]struct{})
		}
		owners[legacy][feed.sourceKey()] = struct{}{}
	}

	bans, err := store.BanList()
	if err != nil {
		return fmt.Errorf("list bans: %w", err)
	}
	updates := make(map[string]storage.BanEntry)
	for ip, entry := range bans {
		if len(entry.Claims) == 0 {
			continue
		}
		changed := false
		claims := make(map[string]time.Time, len(entry.Claims))
		for source, expiry := range entry.Claims {
			if !strings.HasPrefix(source, "blocklist:") ||
				strings.HasPrefix(source, "blocklist:sha256:") ||
				strings.HasPrefix(source, "blocklist:legacy:sha256:") {
				keepLaterClaim(claims, source, expiry)
				continue
			}
			changed = true
			targets := owners[source]
			if len(targets) == 1 {
				for target := range targets {
					keepLaterClaim(claims, target, expiry)
				}
			} else {
				keepLaterClaim(claims,
					fmt.Sprintf("blocklist:legacy:sha256:%x", sha256.Sum256([]byte(source))), expiry)
			}
		}
		if changed {
			entry.Claims = claims
			updates[ip] = entry
		}
	}
	if err := store.BanPutMany(updates); err != nil {
		return fmt.Errorf("write migrated ban claims: %w", err)
	}
	return nil
}

func keepLaterClaim(claims map[string]time.Time, source string, expiry time.Time) {
	current, exists := claims[source]
	if !exists || !current.IsZero() && (expiry.IsZero() || current.Before(expiry)) {
		claims[source] = expiry
	}
}

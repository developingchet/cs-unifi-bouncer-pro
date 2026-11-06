package firewall

import (
	"fmt"
	"strings"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
)

func cacheKey(site, name string) string {
	return site + "\x00" + name
}

func cacheName(key string) string {
	if i := strings.IndexByte(key, 0); i >= 0 {
		return key[i+1:]
	}
	return key
}

func getCachedPolicy(store storage.Store, site, name string) (*storage.PolicyRecord, error) {
	return store.GetPolicy(cacheKey(site, name))
}

func setCachedPolicy(store storage.Store, site, name string, rec storage.PolicyRecord) error {
	return store.SetPolicy(cacheKey(site, name), rec)
}

func deleteCachedPolicy(store storage.Store, site, name string) error {
	return store.DeletePolicy(cacheKey(site, name))
}

// MigrateCacheKeys moves group and policy records stored under their bare
// name, as 1.x stored them, to the site-scoped keys used since. A record
// already stored under its scoped key wins and the bare one is dropped.
// Records without a site are left alone: no site ever matched them. It
// returns how many records it moved or dropped.
func MigrateCacheKeys(store storage.Store) (int, error) {
	groups, err := store.ListGroups()
	if err != nil {
		return 0, fmt.Errorf("list groups: %w", err)
	}
	policies, err := store.ListPolicies()
	if err != nil {
		return 0, fmt.Errorf("list policies: %w", err)
	}
	moved := 0
	for key, rec := range groups {
		if strings.IndexByte(key, 0) >= 0 || rec.Site == "" {
			continue
		}
		if _, exists := groups[cacheKey(rec.Site, key)]; !exists {
			if err := store.SetGroup(cacheKey(rec.Site, key), rec); err != nil {
				return moved, fmt.Errorf("migrate group %s: %w", key, err)
			}
		}
		if err := store.DeleteGroup(key); err != nil {
			return moved, fmt.Errorf("remove old group key %s: %w", key, err)
		}
		moved++
	}
	for key, rec := range policies {
		if strings.IndexByte(key, 0) >= 0 || rec.Site == "" {
			continue
		}
		if _, exists := policies[cacheKey(rec.Site, key)]; !exists {
			if err := store.SetPolicy(cacheKey(rec.Site, key), rec); err != nil {
				return moved, fmt.Errorf("migrate policy %s: %w", key, err)
			}
		}
		if err := store.DeletePolicy(key); err != nil {
			return moved, fmt.Errorf("remove old policy key %s: %w", key, err)
		}
		moved++
	}
	return moved, nil
}

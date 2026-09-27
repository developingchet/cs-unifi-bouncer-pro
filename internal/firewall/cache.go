package firewall

import (
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
	rec, err := store.GetPolicy(cacheKey(site, name))
	if err != nil || rec != nil {
		return rec, err
	}
	rec, err = store.GetPolicy(name)
	if err != nil || rec == nil || rec.Site != site {
		return nil, err
	}
	if err := store.SetPolicy(cacheKey(site, name), *rec); err != nil {
		return nil, err
	}
	if err := store.DeletePolicy(name); err != nil {
		return nil, err
	}
	return rec, nil
}

func setCachedPolicy(store storage.Store, site, name string, rec storage.PolicyRecord) error {
	if err := store.SetPolicy(cacheKey(site, name), rec); err != nil {
		return err
	}
	legacy, err := store.GetPolicy(name)
	if err != nil {
		return err
	}
	if legacy != nil && legacy.Site == site {
		return store.DeletePolicy(name)
	}
	return nil
}

func deleteCachedPolicy(store storage.Store, site, name string) error {
	if err := store.DeletePolicy(cacheKey(site, name)); err != nil {
		return err
	}
	legacy, err := store.GetPolicy(name)
	if err != nil {
		return err
	}
	if legacy != nil && legacy.Site == site {
		return store.DeletePolicy(name)
	}
	return nil
}

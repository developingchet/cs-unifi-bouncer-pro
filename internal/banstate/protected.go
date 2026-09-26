package banstate

import (
	"fmt"
	"net"
	"sort"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/decision"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
)

// DropUnbannable deletes stored bans the filters would now refuse: addresses
// covered by BLOCK_WHITELIST, private ranges, and ranges broader than /8 or
// /32. A ban applied before the whitelist gained its address (or by a version
// without the range guard) otherwise stays enforced until its decision ends.
// Reconcile then removes the addresses from the controller. It returns the
// deleted keys in order. Run before the firewall manager loads the database.
func DropUnbannable(store storage.Store, whitelist []*net.IPNet) ([]string, error) {
	bans, err := store.BanList()
	if err != nil {
		return nil, fmt.Errorf("list bans: %w", err)
	}
	var dropped []string
	for key, entry := range bans {
		if decision.Unbannable(key, entry.IPv6, whitelist) {
			dropped = append(dropped, key)
		}
	}
	sort.Strings(dropped)
	for _, key := range dropped {
		if err := store.BanDelete(key); err != nil {
			return nil, fmt.Errorf("delete ban %s: %w", key, err)
		}
	}
	return dropped, nil
}

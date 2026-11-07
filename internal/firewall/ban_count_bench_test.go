package firewall

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/rs/zerolog"
)

// benchSites is the site count of the ban-database benchmarks.
var benchSites = []string{"site-a", "site-b"}

// newBenchManager loads a legacy-mode manager for benchSites over a bbolt
// ban database holding bans IPv4 addresses, all already on the shards.
func newBenchManager(b *testing.B, bans int) *managerImpl {
	b.Helper()
	store, err := storage.NewBboltStore(b.TempDir(), zerolog.Nop(), 0)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = store.Close() })
	entries := make(map[string]storage.BanEntry, bans)
	for i := range bans {
		ip := fmt.Sprintf("45.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff)
		entries[ip] = storage.BanEntry{Claims: map[string]time.Time{"bench": {}}}
	}
	if err := store.BanPutMany(entries); err != nil {
		b.Fatal(err)
	}
	cfg := defaultManagerConfig()
	cfg.GroupCapacityV4 = 10_000
	mgr := NewManager(cfg, testutil.NewMockController(), store, zoneTestNamerB(b), zerolog.Nop()).(*managerImpl)
	ctx := context.Background()
	if err := mgr.LoadInfrastructure(ctx, benchSites); err != nil {
		b.Fatal(err)
	}
	if _, err := mgr.Reconcile(ctx, benchSites); err != nil {
		b.Fatal(err)
	}
	return mgr
}

// BenchmarkSyncDirtyIdle measures a sync tick with nothing to flush over a
// 50k-ban database: the per-tick cost beyond the controller writes.
func BenchmarkSyncDirtyIdle(b *testing.B) {
	mgr := newBenchManager(b, 50_000)
	ctx := context.Background()
	for b.Loop() {
		if err := mgr.SyncDirty(ctx, benchSites); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkReconcileNoDrift measures a reconcile of two sites whose shards
// already match a 50k-ban database.
func BenchmarkReconcileNoDrift(b *testing.B) {
	mgr := newBenchManager(b, 50_000)
	ctx := context.Background()
	for b.Loop() {
		if _, err := mgr.Reconcile(ctx, benchSites); err != nil {
			b.Fatal(err)
		}
	}
}

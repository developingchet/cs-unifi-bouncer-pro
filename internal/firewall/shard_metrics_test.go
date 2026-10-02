package firewall

import (
	"context"
	"strconv"
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/prometheus/client_golang/prometheus"
	promtest "github.com/prometheus/client_golang/prometheus/testutil"
)

// perShardSeries counts the series of the per-shard metrics.
func perShardSeries() int {
	total := 0
	for _, vec := range []prometheus.Collector{metrics.FirewallGroupSize, metrics.ShardOccupancy,
		metrics.ShardIPCount, metrics.ShardSyncTotal, metrics.ShardSyncDuration} {
		total += promtest.CollectAndCount(vec)
	}
	return total
}

// TestRemovedShardsLeaveNoMetricSeries: when a shard is drained after a
// rebalance or pruned from the tail, its per-shard series must disappear
// instead of reporting the last value forever.
func TestRemovedShardsLeaveNoMetricSeries(t *testing.T) {
	ctx := context.Background()
	// Each shard owns one series in each of the five per-shard metrics.
	const seriesPerShard = 5
	setup := func(t *testing.T) *ShardManager {
		t.Helper()
		metrics.FirewallGroupSize.Reset()
		metrics.ShardOccupancy.Reset()
		metrics.ShardIPCount.Reset()
		metrics.ShardSyncTotal.Reset()
		metrics.ShardSyncDuration.Reset()
		sm := newV4ShardManager(t, 10, testutil.NewMockController(), newBboltStore(t))
		shard0 := makeActiveShard(t, sm, 0, 7)
		shard1 := makeActiveShard(t, sm, 1, 3)
		setupShards(t, sm, []*Shard{shard0, shard1})
		for _, s := range []*Shard{shard0, shard1} {
			idx := strconv.Itoa(s.Index)
			metrics.ShardIPCount.WithLabelValues("v4", idx, testSite).Set(1)
			metrics.ShardSyncTotal.WithLabelValues("v4", idx, testSite, "ok").Inc()
			metrics.ShardSyncDuration.WithLabelValues("v4", idx, testSite).Observe(1)
		}
		sm.mu.Lock()
		sm.updateMetricsLocked()
		sm.mu.Unlock()
		if got := perShardSeries(); got != 2*seriesPerShard {
			t.Fatalf("setup produced %d series, want %d", got, 2*seriesPerShard)
		}
		return sm
	}

	t.Run("drained donor", func(t *testing.T) {
		sm := setup(t)
		if n := sm.Rebalance(ctx); n != 1 {
			t.Fatalf("Rebalance() = %d, want 1", n)
		}
		if err := sm.drainDraining(ctx); err != nil {
			t.Fatal(err)
		}
		if got := perShardSeries(); got != seriesPerShard {
			t.Errorf("%d series remain after draining one of two shards, want %d", got, seriesPerShard)
		}
	})

	t.Run("pruned tail", func(t *testing.T) {
		sm := setup(t)
		sm.fam.Shards[1].IPs.Replace(nil)
		sm.fam.Shards[1].State = ShardStateActive
		if err := sm.RemoveTail(); err != nil {
			t.Fatal(err)
		}
		if got := perShardSeries(); got != seriesPerShard {
			t.Errorf("%d series remain after pruning one of two shards, want %d", got, seriesPerShard)
		}
	})
}

// TestEnsureShards_SetsShardIPCountForCleanShards: a shard whose controller
// content matches is never flushed after a restart, so its count must be set
// when it is loaded.
func TestEnsureShards_SetsShardIPCountForCleanShards(t *testing.T) {
	metrics.ShardIPCount.Reset()
	ctrl := testutil.NewMockController()
	ctrl.SetGroups(testSite, []controller.FirewallGroup{
		{ID: "g0", Name: "crowdsec-block-v4-0", GroupType: "address-group", GroupMembers: []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"}},
	})
	sm := newV4ShardManager(t, 5, ctrl, newBboltStore(t))
	if err := sm.EnsureShards(context.Background()); err != nil {
		t.Fatalf("EnsureShards: %v", err)
	}
	if got := promtest.ToFloat64(metrics.ShardIPCount.WithLabelValues("v4", "0", testSite)); got != 3 {
		t.Errorf("shard_ip_count = %v, want 3", got)
	}
}

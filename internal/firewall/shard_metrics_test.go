package firewall

import (
	"context"
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	promtest "github.com/prometheus/client_golang/prometheus/testutil"
)

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

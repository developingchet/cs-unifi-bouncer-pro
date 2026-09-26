package firewall

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	promtest "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/rs/zerolog"
)

// TestShardCreate_BacksOffAndReportsUnsyncedIPs verifies that a shard the
// controller refuses to create is retried with backoff rather than every
// tick, and that its bans are reported as not enforced until it exists.
func TestShardCreate_BacksOffAndReportsUnsyncedIPs(t *testing.T) {
	ctx := context.Background()
	const site = "backoff-site"
	ctrl := testutil.NewMockController()
	sm := NewShardManager(site, false, 10, zoneTestNamer(t), ctrl, testutil.NewMockStore(), zerolog.Nop(), 0, nil, false, "zone")
	if err := sm.EnsureShards(ctx); err != nil {
		t.Fatalf("EnsureShards: %v", err)
	}
	for _, ip := range []string{"203.0.113.1", "203.0.113.2"} {
		if _, _, err := sm.Add(ctx, ip); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}
	unsynced := func() float64 { return promtest.ToFloat64(metrics.UnsyncedIPs.WithLabelValues("v4", site)) }
	failures := func() float64 {
		return promtest.ToFloat64(metrics.ShardCreateFailures.WithLabelValues("v4", site))
	}

	ctrl.SetError("CreateTrafficMatchingList", errors.New("UniFi API returned HTTP 422: too many entries"))
	if err := sm.FlushDirty(ctx); err == nil {
		t.Fatal("FlushDirty succeeded although the create was refused")
	}
	if got := failures(); got != 1 {
		t.Errorf("shard_create_failures_total = %v, want 1", got)
	}
	if got := unsynced(); got != 2 {
		t.Errorf("unsynced_ips = %v, want 2", got)
	}

	// Within the backoff window no create is attempted.
	calls := ctrl.Calls("CreateTrafficMatchingList")
	if err := sm.FlushDirty(ctx); err != nil {
		t.Fatalf("FlushDirty during backoff: %v", err)
	}
	if got := ctrl.Calls("CreateTrafficMatchingList"); got != calls {
		t.Fatalf("create retried during backoff: %d calls, want %d", got, calls)
	}

	// Once the window passes the create is retried and succeeds.
	sm.mu.Lock()
	shard := sm.fam.Shards[0]
	if time.Until(shard.createRetryAt) < createBackoffBase/2 {
		t.Errorf("retry scheduled too soon: %v", time.Until(shard.createRetryAt))
	}
	shard.createRetryAt = time.Now().Add(-time.Second)
	sm.mu.Unlock()
	if err := sm.FlushDirty(ctx); err != nil {
		t.Fatalf("FlushDirty after backoff: %v", err)
	}
	if got := unsynced(); got != 0 {
		t.Errorf("unsynced_ips after create = %v, want 0", got)
	}
	if got := promtest.ToFloat64(metrics.ShardIPCount.WithLabelValues("v4", "0", site)); got != 2 {
		t.Errorf("shard_ip_count = %v, want 2", got)
	}
}

func TestCreateBackoffGrowsAndCaps(t *testing.T) {
	sm := NewShardManager("s", false, 10, zoneTestNamer(t), testutil.NewMockController(), testutil.NewMockStore(), zerolog.Nop(), 0, nil, false, "zone")
	shard := &Shard{Name: "crowdsec-block-v4-0", Family: "v4", IPs: NewIPSet()}
	var prev time.Duration
	for i := 1; i <= 10; i++ {
		sm.recordCreateFailure(shard, 0, errors.New("refused"))
		wait := time.Until(shard.createRetryAt)
		if wait > createBackoffMax {
			t.Fatalf("failure %d: wait %v exceeds cap", i, wait)
		}
		if i > 1 && wait+time.Second < prev && prev < createBackoffMax {
			t.Fatalf("failure %d: wait shrank from %v to %v", i, prev, wait)
		}
		prev = wait
	}
	if prev < createBackoffMax-time.Minute {
		t.Errorf("backoff never reached the cap: %v", prev)
	}
}

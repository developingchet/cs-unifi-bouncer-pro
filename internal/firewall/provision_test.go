package firewall

import (
	"context"
	"errors"
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	promtest "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/rs/zerolog"
)

// TestEnsurePolicies_OneRefusedShardDoesNotOrphanTheRest reproduces groups
// that existed on the controller with no block policy: a refused policy must
// not stop the policies of later shards, and the refused shard's bans must be
// reported as unenforced until a later sync provisions it.
func TestEnsurePolicies_OneRefusedShardDoesNotOrphanTheRest(t *testing.T) {
	ctx := context.Background()
	const site = "provision-site"
	ctrl := testutil.NewMockController()
	sm := NewShardManager(site, false, 2, zoneTestNamer(t), ctrl, testutil.NewMockStore(), zerolog.Nop(), 0, false, "zone")
	if err := sm.EnsureShards(ctx); err != nil {
		t.Fatalf("EnsureShards: %v", err)
	}
	for _, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		if _, _, err := sm.Add(ctx, ip); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}
	if err := sm.FlushDirty(ctx); err != nil {
		t.Fatalf("FlushDirty: %v", err)
	}
	if got := len(sm.GroupRefs()); got != 2 {
		t.Fatalf("active shards = %d, want 2", got)
	}
	zm := newTestZoneManager(ctrl, testutil.NewMockStore(), zoneTestNamer(t))
	if err := zm.Bootstrap(ctx, []string{site}); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	unsynced := func() float64 { return promtest.ToFloat64(metrics.UnsyncedIPs.WithLabelValues("v4", site)) }

	// The mock fails the next call only: shard 0 (two IPs) is refused.
	ctrl.SetError("CreateZonePolicy", errors.New("UniFi API returned HTTP 400: refused"))
	err := zm.EnsurePolicies(ctx, site, sm, nil)
	if !IsShardProvisionError(err) {
		t.Fatalf("EnsurePolicies error = %v, want a ShardProvisionError", err)
	}
	if policies, _ := ctrl.ListZonePolicies(ctx, site); len(policies) != 1 {
		t.Errorf("policies after refusal = %d, want 1 (shard 1 still provisioned)", len(policies))
	}
	if got := unsynced(); got != 2 {
		t.Errorf("unsynced_ips = %v, want 2 (shard 0 has no policy)", got)
	}

	if err := zm.EnsurePolicies(ctx, site, sm, nil); err != nil {
		t.Fatalf("EnsurePolicies after recovery: %v", err)
	}
	if err := sm.FlushDirty(ctx); err != nil {
		t.Fatalf("FlushDirty after recovery: %v", err)
	}
	policies, _ := ctrl.ListZonePolicies(ctx, site)
	if len(policies) != 2 {
		t.Errorf("policies = %d, want 2", len(policies))
	}
	if got := unsynced(); got != 0 {
		t.Errorf("unsynced_ips after recovery = %v, want 0", got)
	}
}

func TestShardProvisionError(t *testing.T) {
	inner := errors.New("refused")
	err := provisionFailure([]error{inner})
	if !IsShardProvisionError(err) || !errors.Is(err, inner) {
		t.Fatalf("provisionFailure = %v, want a ShardProvisionError wrapping %v", err, inner)
	}
	if provisionFailure(nil) != nil {
		t.Error("provisionFailure(nil) != nil")
	}
	if IsShardProvisionError(errors.New("list failed")) {
		t.Error("plain error reported as a shard provision error")
	}
}

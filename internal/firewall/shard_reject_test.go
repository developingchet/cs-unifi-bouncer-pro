package firewall

import (
	"context"
	"slices"
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/rs/zerolog"
)

// TestSyncShard_RefusedMemberDoesNotBlockTheShard: the classic API refuses
// "203.0.113.77/32" with FirewallGroupInvalidArgs. The shard must still sync
// its other members, and the refusal must not count toward the circuit
// breaker, which would otherwise stop every other ban.
func TestSyncShard_RefusedMemberDoesNotBlockTheShard(t *testing.T) {
	ctrl := testutil.NewMockController()
	ctrl.RefuseGroupMember("203.0.113.77/32")
	sm := NewShardManager(testSite, false, 10, testNamer(t), ctrl, testutil.NewMockStore(), zerolog.Nop(), 0, false, "legacy")
	syncErrors := 0
	sm.SetSyncCallbacks(func() {}, func() { syncErrors++ })

	ctx := context.Background()
	for _, ip := range []string{"198.51.100.1", "203.0.113.77/32", "198.51.100.2"} {
		if err := sm.AddIP(ctx, ip); err != nil {
			t.Fatal(err)
		}
	}
	if err := sm.FlushDirty(ctx); err != nil {
		t.Fatalf("FlushDirty: %v", err)
	}

	groups, err := ctrl.ListFirewallGroups(ctx, testSite)
	if err != nil || len(groups) != 1 {
		t.Fatalf("groups = %+v, %v", groups, err)
	}
	want := []string{"198.51.100.1", "198.51.100.2"}
	if got := groups[0].GroupMembers; !slices.Equal(got, want) {
		t.Fatalf("members = %v, want %v", got, want)
	}
	if syncErrors != 0 {
		t.Fatalf("refused member counted %d sync errors against the breaker", syncErrors)
	}

	// Releasing the refused entry forgets the rejection.
	sm.RemoveIP("203.0.113.77/32")
	if err := sm.AddIP(ctx, "198.51.100.3"); err != nil {
		t.Fatal(err)
	}
	if err := sm.FlushDirty(ctx); err != nil {
		t.Fatalf("FlushDirty after release: %v", err)
	}
	shard := sm.fam.Shards[0]
	if len(shard.rejected) != 0 {
		t.Fatalf("rejected = %v, want empty after release", shard.rejected)
	}
}

func badRequest(arg string) error {
	return &controller.ErrBadRequest{Body: "refused", Arg: arg}
}

func TestSyncShard_UnnamedBadRequestIsNotABreakerFailure(t *testing.T) {
	ctrl := testutil.NewMockController()
	sm := NewShardManager(testSite, false, 10, testNamer(t), ctrl, testutil.NewMockStore(), zerolog.Nop(), 0, false, "legacy")
	syncErrors := 0
	sm.SetSyncCallbacks(func() {}, func() { syncErrors++ })
	ctx := context.Background()
	if err := sm.AddIP(ctx, "198.51.100.1"); err != nil {
		t.Fatal(err)
	}
	if err := sm.FlushDirty(ctx); err != nil {
		t.Fatalf("first flush: %v", err)
	}

	ctrl.RefuseGroupMember("198.51.100.9")
	if err := sm.AddIP(ctx, "198.51.100.9"); err != nil {
		t.Fatal(err)
	}
	// A refused member that the controller names is quarantined; with an
	// unnamed 400 the write fails but the breaker is still not charged.
	ctrl.SetError("UpdateFirewallGroup", badRequest(""))
	if err := sm.FlushDirty(ctx); err == nil {
		t.Fatal("expected the unnamed 400 to surface")
	}
	if syncErrors != 0 {
		t.Fatalf("400 counted %d sync errors against the breaker", syncErrors)
	}
}

// TestSyncShard_RefusedMemberDoesNotRewriteTheShardEveryTick: a member the
// controller refuses stays in the desired set, but it must not keep the shard
// dirty, or the whole shard is written again on every tick.
func TestSyncShard_RefusedMemberDoesNotRewriteTheShardEveryTick(t *testing.T) {
	ctrl := testutil.NewMockController()
	ctrl.RefuseGroupMember("203.0.113.77/32")
	sm := NewShardManager(testSite, false, 10, testNamer(t), ctrl, testutil.NewMockStore(), zerolog.Nop(), 0, false, "legacy")
	ctx := context.Background()
	for _, ip := range []string{"198.51.100.1", "203.0.113.77/32"} {
		if err := sm.AddIP(ctx, ip); err != nil {
			t.Fatal(err)
		}
	}
	if err := sm.FlushDirty(ctx); err != nil {
		t.Fatalf("FlushDirty: %v", err)
	}
	shard := sm.fam.Shards[0]
	if shard.IPs.IsDirty() {
		t.Fatal("shard is still dirty after every acceptable member was written")
	}

	writes := ctrl.Calls("UpdateFirewallGroup")
	for range 3 {
		if err := sm.FlushDirty(ctx); err != nil {
			t.Fatalf("FlushDirty: %v", err)
		}
	}
	if got := ctrl.Calls("UpdateFirewallGroup"); got != writes {
		t.Errorf("UpdateFirewallGroup calls grew from %d to %d across idle ticks", writes, got)
	}

	// A new member still triggers a write, which keeps leaving the refused one out.
	if err := sm.AddIP(ctx, "198.51.100.2"); err != nil {
		t.Fatal(err)
	}
	if err := sm.FlushDirty(ctx); err != nil {
		t.Fatalf("FlushDirty: %v", err)
	}
	if got := ctrl.Calls("UpdateFirewallGroup"); got != writes+1 {
		t.Errorf("UpdateFirewallGroup calls = %d, want %d after one new member", got, writes+1)
	}
	if shard.IPs.IsDirty() {
		t.Error("shard dirty again after the follow-up write")
	}
}

// TestMarkRemoteDriftIgnoresRefusedMembers: the controller never holds a
// refused member, so its absence is not drift.
func TestMarkRemoteDriftIgnoresRefusedMembers(t *testing.T) {
	ctrl := testutil.NewMockController()
	ctrl.RefuseGroupMember("203.0.113.77/32")
	sm := NewShardManager(testSite, false, 10, testNamer(t), ctrl, testutil.NewMockStore(), zerolog.Nop(), 0, false, "legacy")
	ctx := context.Background()
	for _, ip := range []string{"198.51.100.1", "203.0.113.77/32"} {
		if err := sm.AddIP(ctx, ip); err != nil {
			t.Fatal(err)
		}
	}
	if err := sm.FlushDirty(ctx); err != nil {
		t.Fatalf("FlushDirty: %v", err)
	}

	missing, extra, err := sm.MarkRemoteDrift(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if missing != 0 || extra != 0 {
		t.Errorf("drift = %d missing, %d extra; want none", missing, extra)
	}
	if sm.fam.Shards[0].IPs.IsDirty() {
		t.Error("shard marked dirty by drift detection")
	}
}

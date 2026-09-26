package firewall

import (
	"context"
	"slices"
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/rs/zerolog"
)

// TestSyncShard_RefusedMemberDoesNotBlockTheShard reproduces a live failure:
// the classic API refuses "203.0.113.77/32" with FirewallGroupInvalidArgs,
// the shard failed on every flush, and the failures opened the circuit
// breaker, which stopped every other ban.
func TestSyncShard_RefusedMemberDoesNotBlockTheShard(t *testing.T) {
	ctrl := testutil.NewMockController()
	ctrl.RefuseGroupMember("203.0.113.77/32")
	sm := NewShardManager(testSite, false, 10, testNamer(t), ctrl, testutil.NewMockStore(), zerolog.Nop(), 0, nil, false, "legacy")
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
	sm := NewShardManager(testSite, false, 10, testNamer(t), ctrl, testutil.NewMockStore(), zerolog.Nop(), 0, nil, false, "legacy")
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

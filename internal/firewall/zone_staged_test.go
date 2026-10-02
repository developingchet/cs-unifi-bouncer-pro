package firewall

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/rs/zerolog"
)

// stagedPolicyFixture holds a zone manager with one provisioned shard and the
// block policy it created.
type stagedPolicyFixture struct {
	ctrl  *testutil.MockController
	zm    *ZoneManager
	shard *ShardManager
	block controller.ZonePolicy
}

func newStagedPolicyFixture(t *testing.T) *stagedPolicyFixture {
	t.Helper()
	ctx := context.Background()
	ctrl := testutil.NewMockController()
	store := newBboltStore(t)
	shard := ensuredZoneV4Shard(t, ctrl, store)
	zm := NewZoneManager(ZoneConfig{
		ZonePairs:   []config.ZonePair{{Src: "wan", Dst: "lan"}},
		Description: "test",
	}, zoneTestNamer(t), ctrl, store, zerolog.Nop())
	if err := zm.Bootstrap(ctx, []string{testSite}); err != nil {
		t.Fatal(err)
	}
	if err := zm.EnsurePolicies(ctx, testSite, shard, nil); err != nil {
		t.Fatal(err)
	}
	policies, err := ctrl.ListZonePolicies(ctx, testSite)
	if err != nil || len(policies) != 1 {
		t.Fatalf("setup policies = %+v, %v", policies, err)
	}
	return &stagedPolicyFixture{ctrl: ctrl, zm: zm, shard: shard, block: policies[0]}
}

// stagedCopy returns the staged copy a replacement of f.block would create.
func (f *stagedPolicyFixture) stagedCopy() controller.ZonePolicy {
	staged := f.block
	staged.ID = "staged-" + f.block.ID
	staged.Name = stagedPolicyName(f.block)
	return staged
}

func (f *stagedPolicyFixture) policyNames(t *testing.T) []string {
	t.Helper()
	policies, err := f.ctrl.ListZonePolicies(context.Background(), testSite)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(policies))
	for _, p := range policies {
		names = append(names, p.Name)
	}
	return names
}

// TestStagedPolicyKeptWhenItIsTheOnlyCoverage reproduces a replacement that
// deleted the old block policy and then failed to create the new one: the
// staged copy is all that blocks the shard, so the orphan sweep that follows
// the failed provisioning must leave it alone.
func TestStagedPolicyKeptWhenItIsTheOnlyCoverage(t *testing.T) {
	ctx := context.Background()
	f := newStagedPolicyFixture(t)
	staged := f.stagedCopy()
	f.ctrl.SetPolicies(testSite, []controller.ZonePolicy{staged})
	if err := deleteCachedPolicy(f.zm.store, testSite, f.block.Name); err != nil {
		t.Fatal(err)
	}
	f.ctrl.SetError("CreateZonePolicy", errors.New("controller unavailable"))

	if err := f.zm.EnsurePolicies(ctx, testSite, f.shard, nil); !IsShardProvisionError(err) {
		t.Fatalf("EnsurePolicies error = %v, want a shard provisioning failure", err)
	}
	if names := f.policyNames(t); len(names) != 1 || names[0] != staged.Name {
		t.Fatalf("policies after failed create = %v, want only the staged copy", names)
	}

	if err := f.zm.EnsurePolicies(ctx, testSite, f.shard, nil); err != nil {
		t.Fatalf("EnsurePolicies retry: %v", err)
	}
	if names := f.policyNames(t); len(names) != 1 || names[0] != f.block.Name {
		t.Errorf("policies after retry = %v, want only %s", names, f.block.Name)
	}
}

// TestStagedPolicyRemovedOnceTheShardHasItsBlockPolicy covers a staged copy
// left behind after the replacement was created.
func TestStagedPolicyRemovedOnceTheShardHasItsBlockPolicy(t *testing.T) {
	f := newStagedPolicyFixture(t)
	f.ctrl.SetPolicies(testSite, []controller.ZonePolicy{f.block, f.stagedCopy()})

	if err := f.zm.EnsurePolicies(context.Background(), testSite, f.shard, nil); err != nil {
		t.Fatal(err)
	}
	if names := f.policyNames(t); len(names) != 1 || names[0] != f.block.Name {
		t.Errorf("policies = %v, want only %s", names, f.block.Name)
	}
}

// TestStagedPolicyOfRemovedShardIsDeleted covers a staged copy whose shard no
// longer exists: nothing is left for it to protect.
func TestStagedPolicyOfRemovedShardIsDeleted(t *testing.T) {
	f := newStagedPolicyFixture(t)
	abandoned := f.stagedCopy()
	abandoned.TrafficMatchingListIDs = []string{"deleted-shard"}
	abandoned.Name = stagedPolicyName(abandoned)
	f.ctrl.SetPolicies(testSite, []controller.ZonePolicy{f.block, abandoned})

	if err := f.zm.EnsurePolicies(context.Background(), testSite, f.shard, nil); err != nil {
		t.Fatal(err)
	}
	for _, name := range f.policyNames(t) {
		if strings.HasPrefix(name, stagedPolicyPrefix) {
			t.Errorf("staged policy %s of a removed shard was kept", name)
		}
	}
}

// TestStagedPolicyWithForeignDescriptionIsKept guards policies the bouncer
// does not own.
func TestStagedPolicyWithForeignDescriptionIsKept(t *testing.T) {
	f := newStagedPolicyFixture(t)
	foreign := f.stagedCopy()
	foreign.Description = "someone else"
	f.ctrl.SetPolicies(testSite, []controller.ZonePolicy{f.block, foreign})

	if err := f.zm.EnsurePolicies(context.Background(), testSite, f.shard, nil); err != nil {
		t.Fatal(err)
	}
	if names := f.policyNames(t); len(names) != 2 {
		t.Errorf("policies = %v, want the foreign policy kept", names)
	}
}

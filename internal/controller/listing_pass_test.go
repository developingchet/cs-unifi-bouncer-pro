package controller_test

import (
	"context"
	"errors"
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
)

const passSite = "default"

func listNames(t *testing.T, ctx context.Context, c controller.Controller) []string {
	t.Helper()
	tmls, err := c.ListTrafficMatchingLists(ctx, passSite)
	if err != nil {
		t.Fatalf("ListTrafficMatchingLists: %v", err)
	}
	names := make([]string, 0, len(tmls))
	for _, tml := range tmls {
		names = append(names, tml.Name)
	}
	return names
}

func newPassMock() (*testutil.MockController, controller.Controller) {
	mock := testutil.NewMockController()
	mock.SetTMLs(passSite, []controller.TrafficMatchingList{
		{ID: "a", Name: "list-a", Type: "IPV4_ADDRESSES"},
		{ID: "b", Name: "list-b", Type: "IPV4_ADDRESSES"},
	})
	return mock, controller.WithListingPasses(mock)
}

func TestListingPassListsOnce(t *testing.T) {
	mock, c := newPassMock()
	ctx := context.Background()

	listNames(t, ctx, c)
	listNames(t, ctx, c)
	if got := mock.Calls("ListTrafficMatchingLists"); got != 2 {
		t.Fatalf("outside a pass: %d listings, want 2", got)
	}

	passCtx, end := controller.BeginPass(ctx)
	defer end()
	mock.ResetCalls()
	listNames(t, passCtx, c)
	listNames(t, passCtx, c)
	if got := mock.Calls("ListTrafficMatchingLists"); got != 1 {
		t.Fatalf("inside a pass: %d listings, want 1", got)
	}

	nested, endNested := controller.BeginPass(passCtx)
	listNames(t, nested, c)
	endNested()
	listNames(t, passCtx, c)
	if got := mock.Calls("ListTrafficMatchingLists"); got != 1 {
		t.Fatalf("a nested pass fetched again: %d listings, want 1", got)
	}
}

func TestListingPassAppliesWrites(t *testing.T) {
	mock, c := newPassMock()
	ctx, end := controller.BeginPass(context.Background())
	defer end()
	listNames(t, ctx, c)

	created, err := c.CreateTrafficMatchingList(ctx, passSite, controller.TrafficMatchingList{Name: "list-c", Type: "PORTS"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.UpdateTrafficMatchingList(ctx, passSite, controller.TrafficMatchingList{ID: "a", Name: "list-a2", Type: "IPV4_ADDRESSES"}); err != nil {
		t.Fatal(err)
	}
	// A write made outside the pass, through another wrapper of the same
	// controller, reaches the pass too.
	other := controller.WithListingPasses(mock)
	if err := other.DeleteTrafficMatchingList(context.Background(), passSite, "b"); err != nil {
		t.Fatal(err)
	}

	got := listNames(t, ctx, c)
	want := []string{"list-a2", "list-c"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("listing after writes = %v, want %v (created %s)", got, want, created.ID)
	}
}

func TestListingPassFreshListing(t *testing.T) {
	mock, c := newPassMock()
	ctx, end := controller.BeginPass(context.Background())
	defer end()
	listNames(t, ctx, c)

	// Changed behind the wrapper's back, as the UniFi UI would.
	mock.SetTMLs(passSite, []controller.TrafficMatchingList{{ID: "z", Name: "list-z"}})
	if got := listNames(t, ctx, c); len(got) != 2 {
		t.Fatalf("pass listing = %v, want the two lists it first saw", got)
	}
	if got := listNames(t, controller.FreshListing(ctx), c); len(got) != 1 || got[0] != "list-z" {
		t.Fatalf("fresh listing = %v, want [list-z]", got)
	}
	if got := listNames(t, ctx, c); len(got) != 1 || got[0] != "list-z" {
		t.Fatalf("listing after a fresh one = %v, want [list-z]", got)
	}
}

func TestListingPassFailedWrites(t *testing.T) {
	mock, c := newPassMock()
	ctx, end := controller.BeginPass(context.Background())
	defer end()
	listNames(t, ctx, c)

	mock.SetError("UpdateTrafficMatchingList", &controller.ErrBadRequest{Body: "refused"})
	if err := c.UpdateTrafficMatchingList(ctx, passSite, controller.TrafficMatchingList{ID: "a", Name: "x"}); err == nil {
		t.Fatal("update succeeded, want the injected refusal")
	}
	listNames(t, ctx, c)
	if got := mock.Calls("ListTrafficMatchingLists"); got != 1 {
		t.Fatalf("a refused write dropped the listing: %d listings, want 1", got)
	}

	mock.SetError("UpdateTrafficMatchingList", errors.New("connection reset"))
	if err := c.UpdateTrafficMatchingList(ctx, passSite, controller.TrafficMatchingList{ID: "a", Name: "x"}); err == nil {
		t.Fatal("update succeeded, want the injected failure")
	}
	listNames(t, ctx, c)
	if got := mock.Calls("ListTrafficMatchingLists"); got != 2 {
		t.Fatalf("a write of unknown outcome kept the listing: %d listings, want 2", got)
	}
}

func TestListingPassPolicyUpdateRefetches(t *testing.T) {
	mock := testutil.NewMockController()
	mock.SetPolicies(passSite, []controller.ZonePolicy{{ID: "p", Name: "policy", DstIPTMLID: "dst"}})
	c := controller.WithListingPasses(mock)
	ctx, end := controller.BeginPass(context.Background())
	defer end()
	if _, err := c.ListZonePolicies(ctx, passSite); err != nil {
		t.Fatal(err)
	}
	if err := c.UpdateZonePolicy(ctx, passSite, controller.ZonePolicy{ID: "p", Name: "policy"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ListZonePolicies(ctx, passSite); err != nil {
		t.Fatal(err)
	}
	if got := mock.Calls("ListZonePolicies"); got != 2 {
		t.Fatalf("policy listings = %d, want 2: an update must be read back", got)
	}
}

func TestListingPassEndedContextFetches(t *testing.T) {
	mock, c := newPassMock()
	ctx, end := controller.BeginPass(context.Background())
	listNames(t, ctx, c)
	end()
	listNames(t, ctx, c)
	if got := mock.Calls("ListTrafficMatchingLists"); got != 2 {
		t.Fatalf("listings through an ended pass = %d, want 2", got)
	}
}

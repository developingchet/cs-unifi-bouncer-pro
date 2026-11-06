package bouncer

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/banstate"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/rs/zerolog"
	"golang.org/x/time/rate"
)

func newBatchBouncer(t *testing.T) (*Bouncer, *testutil.MockStore, *mockFirewallManager) {
	t.Helper()
	store := testutil.NewMockStore()
	fwMgr := &mockFirewallManager{}
	cfg := &config.Config{UnifiSites: []string{"default"}, BanTTL: 24 * time.Hour}
	b, err := New(cfg, testutil.NewMockController(), store, fwMgr,
		banstate.New(store, fwMgr, cfg.UnifiSites, false), nopRecorder{}, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	return b, store, fwMgr
}

// A block of new bans costs two ban-database writes and one history write
// per batch of decisionBatchSize, instead of three writes per decision.
func TestDecisionBlockBatchesStoreWrites(t *testing.T) {
	tests := []struct {
		name    string
		bans    int
		batches int
	}{
		{"one batch", 40, 1},
		{"several batches", decisionBatchSize*2 + 3, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, store, fwMgr := newBatchBouncer(t)
			b.handleDecisionBlock(context.Background(), banBlock(1, tt.bans), "stream")

			for method, want := range map[string]int{
				"BanPutMany": 2 * tt.batches, "RecordEvents": tt.batches,
				"BanPut": 0, "RecordEvent": 0,
			} {
				if got := store.Calls(method); got != want {
					t.Errorf("%s calls = %d, want %d", method, got, want)
				}
			}
			if fwMgr.applyBanCalls != tt.bans {
				t.Errorf("ApplyBan calls = %d, want %d", fwMgr.applyBanCalls, tt.bans)
			}
			bans, err := store.BanList()
			if err != nil {
				t.Fatal(err)
			}
			pending := 0
			for _, entry := range bans {
				if entry.Pending {
					pending++
				}
			}
			if len(bans) != tt.bans || pending != 0 {
				t.Errorf("stored %d bans, %d pending; want %d, none pending", len(bans), pending, tt.bans)
			}
			events, err := store.ListEvents(0)
			if err != nil || len(events) != tt.bans {
				t.Errorf("history holds %d events (err %v), want %d", len(events), err, tt.bans)
			}
		})
	}
}

// A block that bans and lifts the same address applies the ban first, and
// its history lists the events in decision order.
func TestDecisionBlockKeepsDecisionOrder(t *testing.T) {
	b, store, _ := newBatchBouncer(t)
	block := banBlock(1, 2)
	block.Deleted = []*models.Decision{block.New[0]}
	first, second := *block.New[0].Value, *block.New[1].Value

	b.handleDecisionBlock(context.Background(), block, "stream")

	if banned, _ := store.BanExists(first); banned {
		t.Errorf("%s still banned after its decision was deleted in the same block", first)
	}
	if banned, _ := store.BanExists(second); !banned {
		t.Errorf("%s not banned", second)
	}
	events, err := store.ListEvents(0)
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(events) // ListEvents is newest first
	var got []string
	for _, e := range events {
		got = append(got, e.Action+" "+e.IP)
	}
	want := []string{"ban " + first, "ban " + second, "unban " + first}
	if !slices.Equal(got, want) {
		t.Errorf("events = %v, want %v", got, want)
	}
}

// Two decisions for one address in a batch both hold a claim, and the
// address is banned and recorded in the history once.
func TestDecisionBlockClaimsOneAddressTwice(t *testing.T) {
	b, store, fwMgr := newBatchBouncer(t)
	block := banBlock(1, 2)
	block.New[1].Value = block.New[0].Value
	ip := *block.New[0].Value

	b.handleDecisionBlock(context.Background(), block, "stream")

	entry, err := store.BanGet(ip)
	if err != nil || entry == nil {
		t.Fatalf("BanGet = %v, %v", entry, err)
	}
	if len(entry.Claims) != 2 || entry.Pending {
		t.Errorf("entry = %+v, want two claims and not pending", entry)
	}
	if fwMgr.applyBanCalls != 1 {
		t.Errorf("ApplyBan calls = %d, want 1", fwMgr.applyBanCalls)
	}
	if events, _ := store.ListEvents(0); len(events) != 1 {
		t.Errorf("history holds %d events, want 1", len(events))
	}
}

// A failed ban-database write fails every decision of the batch, and no
// address reaches the firewall without a record.
func TestDecisionBlockStoreFailureFailsBatch(t *testing.T) {
	b, store, fwMgr := newBatchBouncer(t)
	store.SetError("BanPutMany", errors.New("disk full"))
	var errs []error
	inner := b.handler
	b.handler = func(ctx context.Context, jobs []SyncJob) []error {
		errs = inner(ctx, jobs)
		return errs
	}

	b.handleDecisionBlock(context.Background(), banBlock(1, 3), "stream")

	if len(errs) != 3 || slices.Contains(errs, nil) {
		t.Errorf("job errors = %v, want an error for each of 3 jobs", errs)
	}
	if fwMgr.applyBanCalls != 0 {
		t.Errorf("ApplyBan calls = %d, want 0", fwMgr.applyBanCalls)
	}
}

// Under DECISION_RATE_LIMIT, the decisions admitted so far are applied
// before the stream waits for the next token.
func TestDecisionBlockAppliesBeforeRateLimitWait(t *testing.T) {
	b, _, _ := newBatchBouncer(t)
	b.limiter = rate.NewLimiter(rate.Limit(20), 2)
	var sizes []int
	b.handler = func(_ context.Context, jobs []SyncJob) []error {
		sizes = append(sizes, len(jobs))
		return make([]error, len(jobs))
	}

	b.handleDecisionBlock(context.Background(), banBlock(1, 4), "stream")

	if !slices.Equal(sizes, []int{2, 1, 1}) {
		t.Errorf("batch sizes = %v, want [2 1 1]: the burst, then one per token", sizes)
	}
}

package bouncer

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"golang.org/x/time/rate"
)

func TestConsumeStream_OnStartupSyncedFiresOnceAfterFirstBatch(t *testing.T) {
	b := newTestBouncer(t, &config.Config{UnifiSites: []string{"default"}, BanTTL: time.Hour})
	var jobs int
	b.handler = func(_ context.Context, batch []SyncJob) []error { jobs += len(batch); return make([]error, len(batch)) }
	synced := 0
	jobsAtSync := -1
	b.OnStartupSynced(func() {
		synced++
		jobsAtSync = jobs
	})

	stream := make(chan *models.DecisionsStreamResponse)
	runErr := make(chan error, 1)
	done := make(chan error, 1)
	go func() { done <- b.consumeStream(context.Background(), stream, runErr) }()

	id, action, scope, ip, dur := int64(1), "ban", "ip", "203.0.113.7", "1h"
	stream <- &models.DecisionsStreamResponse{New: []*models.Decision{
		{ID: id, Type: &action, Scope: &scope, Value: &ip, Duration: &dur},
	}}
	stream <- &models.DecisionsStreamResponse{}
	runErr <- errors.New("lapi gone")

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("consumeStream returned nil after a stream failure")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("consumeStream did not return")
	}
	if synced != 1 {
		t.Fatalf("OnStartupSynced fired %d times, want 1", synced)
	}
	if jobsAtSync != 1 {
		t.Fatalf("OnStartupSynced fired with %d jobs applied, want 1 (after the first batch)", jobsAtSync)
	}
}

func TestConsumeStream_OnStartupSyncedRunsEveryCallbackInOrder(t *testing.T) {
	b := newTestBouncer(t, &config.Config{UnifiSites: []string{"default"}, BanTTL: time.Hour})
	var order []string
	b.OnStartupSynced(func() { order = append(order, "readiness") })
	b.OnStartupSynced(func() { order = append(order, "reconcile") })

	stream := make(chan *models.DecisionsStreamResponse)
	runErr := make(chan error, 1)
	done := make(chan error, 1)
	go func() { done <- b.consumeStream(context.Background(), stream, runErr) }()
	stream <- &models.DecisionsStreamResponse{}
	stream <- &models.DecisionsStreamResponse{}
	runErr <- context.Canceled
	if err := <-done; err != nil {
		t.Fatalf("consumeStream = %v, want nil on cancellation", err)
	}
	if got := strings.Join(order, ","); got != "readiness,reconcile" {
		t.Fatalf("callbacks ran as %q, want %q", got, "readiness,reconcile")
	}
}

// A first block that shutdown cuts short has not applied every active
// decision, so the startup callbacks (retiring 1.x claims among them) do not
// run.
func TestConsumeStream_StartupCallbacksSkipCutShortFirstBlock(t *testing.T) {
	b := newTestBouncer(t, &config.Config{UnifiSites: []string{"default"}, BanTTL: time.Hour})
	b.limiter = rate.NewLimiter(rate.Limit(0.001), 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	applied := 0
	b.handler = func(_ context.Context, batch []SyncJob) []error {
		applied += len(batch)
		cancel()
		return make([]error, len(batch))
	}
	b.OnStartupSynced(func() { t.Error("OnStartupSynced fired after a cut-short block") })

	stream := make(chan *models.DecisionsStreamResponse, 1)
	stream <- banBlock(1, 3)
	if err := b.consumeStream(ctx, stream, make(chan error)); err != nil {
		t.Fatalf("consumeStream = %v, want nil on shutdown", err)
	}
	if applied != 1 {
		t.Fatalf("applied %d decisions, want 1 before the shutdown", applied)
	}
}

func TestConsumeStream_CancelledRunIsClean(t *testing.T) {
	b := newTestBouncer(t, &config.Config{UnifiSites: []string{"default"}, BanTTL: time.Hour})
	b.OnStartupSynced(func() { t.Error("OnStartupSynced fired without a batch") })
	runErr := make(chan error, 1)
	runErr <- context.Canceled
	if err := b.consumeStream(context.Background(), make(chan *models.DecisionsStreamResponse), runErr); err != nil {
		t.Fatalf("consumeStream = %v, want nil on cancellation", err)
	}
}

package bouncer

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
)

func TestConsumeStream_OnStartupSyncedFiresOnceAfterFirstBatch(t *testing.T) {
	b := newTestBouncer(t, &config.Config{UnifiSites: []string{"default"}, BanTTL: time.Hour})
	var jobs int
	b.handler = func(context.Context, SyncJob) error { jobs++; return nil }
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

func TestConsumeStream_CancelledRunIsClean(t *testing.T) {
	b := newTestBouncer(t, &config.Config{UnifiSites: []string{"default"}, BanTTL: time.Hour})
	b.OnStartupSynced(func() { t.Error("OnStartupSynced fired without a batch") })
	runErr := make(chan error, 1)
	runErr <- context.Canceled
	if err := b.consumeStream(context.Background(), make(chan *models.DecisionsStreamResponse), runErr); err != nil {
		t.Fatalf("consumeStream = %v, want nil on cancellation", err)
	}
}

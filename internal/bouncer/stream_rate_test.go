package bouncer

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"golang.org/x/time/rate"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
)

// startupSyncTime runs consumeStream over one block with the given limiter
// and returns how long OnStartupSynced took to fire and how many jobs ran.
func startupSyncTime(t *testing.T, limiter *rate.Limiter, block *models.DecisionsStreamResponse) (time.Duration, int) {
	t.Helper()
	b := newTestBouncer(t, &config.Config{UnifiSites: []string{"default"}, BanTTL: time.Hour})
	b.limiter = limiter
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	applied := 0
	b.handler = func(_ context.Context, batch []SyncJob) []error {
		applied += len(batch)
		return make([]error, len(batch))
	}
	synced := make(chan struct{})
	b.OnStartupSynced(func() { close(synced); cancel() })

	stream := make(chan *models.DecisionsStreamResponse, 1)
	stream <- block
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- b.consumeStream(ctx, stream, make(chan error)) }()

	select {
	case <-synced:
	case <-time.After(10 * time.Second):
		t.Fatal("OnStartupSynced did not fire after a rate-limited first block")
	}
	elapsed := time.Since(start)
	if err := <-done; err != nil {
		t.Fatalf("consumeStream = %v", err)
	}
	return elapsed, applied
}

// A rate limit slows the first block down without cutting it short, so the
// startup callbacks still run once every decision has been applied.
func TestConsumeStream_StartupCallbacksRunAfterRateLimitedBlock(t *testing.T) {
	_, applied := startupSyncTime(t, rate.NewLimiter(rate.Limit(20), 2), banBlock(1, 8))
	if applied != 8 {
		t.Errorf("applied %d decisions, want 8", applied)
	}
}

// The first block of a stream lists every expired decision the LAPI holds.
// Deletions take no token, so they cannot hold startup back.
func TestConsumeStream_DeletionsAreNotRateLimited(t *testing.T) {
	block := banBlock(1, 2)
	for i := range 200 {
		action, scope, value := "ban", "ip", fmt.Sprintf("198.51.100.%d", i%250)
		block.Deleted = append(block.Deleted, &models.Decision{ID: int64(1000 + i), Type: &action, Scope: &scope, Value: &value})
	}
	elapsed, applied := startupSyncTime(t, rate.NewLimiter(rate.Limit(2), 2), block)
	if elapsed > 3*time.Second {
		t.Errorf("startup synced after %s; 200 deletions must not wait for the limiter", elapsed)
	}
	if applied != 202 {
		t.Errorf("applied %d jobs, want 202 (2 bans and 200 deletions)", applied)
	}
}

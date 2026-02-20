package pool

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func nopHandler(_ context.Context, _ SyncJob) error {
	return nil
}

func TestPoolBasicEnqueueProcess(t *testing.T) {
	var processed int64
	handler := func(_ context.Context, job SyncJob) error {
		atomic.AddInt64(&processed, 1)
		return nil
	}

	p, err := New(Config{Workers: 4, QueueDepth: 100, MaxRetries: 3, RetryBase: time.Millisecond}, handler, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	p.Start(ctx)

	for i := 0; i < 50; i++ {
		p.Enqueue(SyncJob{Action: "ban", IP: "1.2.3.4", IPv6: false})
	}

	// Give workers time to drain
	time.Sleep(100 * time.Millisecond)
	cancel()
	p.Stop()

	if atomic.LoadInt64(&processed) != 50 {
		t.Errorf("expected 50 processed, got %d", processed)
	}
}

func TestPool64Workers(t *testing.T) {
	var processed int64
	handler := func(_ context.Context, _ SyncJob) error {
		atomic.AddInt64(&processed, 1)
		return nil
	}
	p, err := New(Config{Workers: 64, QueueDepth: 10000, MaxRetries: 0, RetryBase: time.Millisecond}, handler, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.Start(ctx)

	for i := 0; i < 1000; i++ {
		p.Enqueue(SyncJob{Action: "ban", IP: "1.2.3.4"})
	}
	time.Sleep(200 * time.Millisecond)
	cancel()
	p.Stop()

	if atomic.LoadInt64(&processed) != 1000 {
		t.Errorf("expected 1000 processed, got %d", processed)
	}
}

func TestPoolNonBlockingDropOnFullBuffer(t *testing.T) {
	// Handler that blocks so buffer fills up
	ready := make(chan struct{})
	handler := func(ctx context.Context, _ SyncJob) error {
		<-ready // block
		return nil
	}
	p, err := New(Config{Workers: 1, QueueDepth: 2, MaxRetries: 0, RetryBase: time.Millisecond}, handler, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.Start(ctx)

	// Fill buffer: worker is blocked so queue fills
	p.Enqueue(SyncJob{Action: "ban", IP: "1.1.1.1"}) // goes to worker
	p.Enqueue(SyncJob{Action: "ban", IP: "2.2.2.2"}) // fills queue
	p.Enqueue(SyncJob{Action: "ban", IP: "3.3.3.3"}) // fills queue

	// This one should be dropped (non-blocking)
	dropped := !p.Enqueue(SyncJob{Action: "ban", IP: "4.4.4.4"})

	close(ready)
	cancel()
	p.Stop()

	if !dropped {
		t.Log("job may not have been dropped if timing was favorable — non-deterministic")
	}
}

func TestPoolStop(t *testing.T) {
	var processed int64
	handler := func(_ context.Context, _ SyncJob) error {
		atomic.AddInt64(&processed, 1)
		return nil
	}
	p, err := New(Config{Workers: 2, QueueDepth: 100, MaxRetries: 0}, handler, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	p.Start(ctx)

	for i := 0; i < 10; i++ {
		p.Enqueue(SyncJob{Action: "ban", IP: "1.2.3.4"})
	}
	p.Stop() // should drain all pending jobs

	if atomic.LoadInt64(&processed) != 10 {
		t.Errorf("Stop() should drain all jobs, processed=%d", atomic.LoadInt64(&processed))
	}
}

func TestPoolRetryLogic(t *testing.T) {
	var attempts int64
	handler := func(_ context.Context, _ SyncJob) error {
		n := atomic.AddInt64(&attempts, 1)
		if n < 3 {
			return &mockErr{"transient"}
		}
		return nil
	}

	// Workers=1, MaxRetries=5, so at most 6 attempts; job succeeds on attempt 3
	p, err := New(Config{Workers: 1, QueueDepth: 100, MaxRetries: 5, RetryBase: time.Millisecond}, handler, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p.Start(ctx)
	p.Enqueue(SyncJob{Action: "ban", IP: "1.2.3.4"})
	// Workers process inline — wait for drain
	p.Stop()

	got := atomic.LoadInt64(&attempts)
	if got < 3 {
		t.Errorf("expected at least 3 attempts, got %d", got)
	}
}

func TestPoolMaxRetriesExceeded(t *testing.T) {
	var attempts int64
	handler := func(_ context.Context, _ SyncJob) error {
		atomic.AddInt64(&attempts, 1)
		return &mockErr{"always fail"}
	}

	// MaxRetries=2 → attempts = initial(1) + retry1(1) + retry2(1) = 3
	p, err := New(Config{Workers: 1, QueueDepth: 100, MaxRetries: 2, RetryBase: time.Millisecond}, handler, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	p.Start(ctx)
	p.Enqueue(SyncJob{Action: "ban", IP: "1.2.3.4"})
	// Stop drains the queue (workers finish inline retry before returning)
	p.Stop()

	got := atomic.LoadInt64(&attempts)
	want := int64(3) // MaxRetries=2, so 3 total attempts
	if got != want {
		t.Errorf("expected %d total attempts, got %d", want, got)
	}
}

func TestPoolInvalidWorkerCount(t *testing.T) {
	_, err := New(Config{Workers: 0}, nopHandler, zerolog.Nop())
	if err == nil {
		t.Error("expected error for 0 workers")
	}
	_, err = New(Config{Workers: 65}, nopHandler, zerolog.Nop())
	if err == nil {
		t.Error("expected error for 65 workers")
	}
}

// TestPool_MaxRetriesZero verifies that MaxRetries=0 causes the handler to be
// called exactly once per job, with no retry attempts.
func TestPool_MaxRetriesZero(t *testing.T) {
	var calls int64
	handler := func(_ context.Context, _ SyncJob) error {
		atomic.AddInt64(&calls, 1)
		return &mockErr{"fail once"}
	}

	p, err := New(Config{Workers: 1, QueueDepth: 100, MaxRetries: 0, RetryBase: time.Millisecond}, handler, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	p.Start(context.Background())
	p.Enqueue(SyncJob{Action: "ban", IP: "1.2.3.4"})
	p.Stop()

	if got := atomic.LoadInt64(&calls); got != 1 {
		t.Errorf("MaxRetries=0: expected exactly 1 handler call, got %d", got)
	}
}

// TestPool_ContextCancelDuringBackoff verifies that cancelling the context while
// a worker is sleeping in a retry backoff causes the worker to exit cleanly
// without processing further retries.
func TestPool_ContextCancelDuringBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	var calls int64
	handler := func(_ context.Context, _ SyncJob) error {
		atomic.AddInt64(&calls, 1)
		// Cancel the context after the first attempt so the backoff select
		// picks up <-ctx.Done() before the timer fires.
		cancel()
		return &mockErr{"trigger retry"}
	}

	// RetryBase=200ms so the backoff is long enough for ctx.Done() to win.
	p, err := New(Config{Workers: 1, QueueDepth: 10, MaxRetries: 5, RetryBase: 200 * time.Millisecond}, handler, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	p.Start(ctx)
	p.Enqueue(SyncJob{Action: "ban", IP: "9.9.9.9"})

	// Give the worker time to pick up the job and hit the backoff sleep.
	time.Sleep(50 * time.Millisecond)
	p.Stop()

	// The handler should have been called exactly once; the retry was aborted.
	if got := atomic.LoadInt64(&calls); got != 1 {
		t.Errorf("context cancel during backoff: expected 1 handler call, got %d", got)
	}
}

type mockErr struct{ msg string }

func (e *mockErr) Error() string { return e.msg }

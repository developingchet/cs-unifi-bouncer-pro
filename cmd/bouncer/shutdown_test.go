package main

import (
	"context"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/rs/zerolog"
)

// After a signal, shutdown waits for every drain (the final usage-metrics
// push among them) within the grace period before returning.
func TestAwaitShutdownWaitsForDrains(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	done <- nil
	webhooks := make(chan struct{})
	close(webhooks)
	metricsPush := make(chan struct{})
	pushed := make(chan struct{})
	go func() {
		time.Sleep(50 * time.Millisecond)
		close(pushed)
		close(metricsPush)
	}()

	cfg := &config.Config{ShutdownGracePeriod: 5 * time.Second}
	if err := awaitShutdown(ctx, cfg, done, zerolog.Nop(), webhooks, metricsPush); err != nil {
		t.Fatalf("awaitShutdown: %v", err)
	}
	select {
	case <-pushed:
	default:
		t.Fatal("awaitShutdown returned before the metrics drain finished")
	}
}

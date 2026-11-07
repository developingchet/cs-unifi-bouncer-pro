package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/firewall"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/webhook"
	"github.com/rs/zerolog"
)

type modeChangeStub struct {
	firewall.Manager
	changed    error
	reconciles atomic.Int32
}

func (s *modeChangeStub) CheckModeChange(context.Context) error { return s.changed }

func (s *modeChangeStub) Reconcile(context.Context, []string) (*firewall.ReconcileResult, error) {
	s.reconciles.Add(1)
	return &firewall.ReconcileResult{}, nil
}

func TestPeriodicReconcileStopsOnModeChange(t *testing.T) {
	changed := &firewall.ModeChangeError{Site: "default", Reason: "the site now has firewall zones"}
	stub := &modeChangeStub{changed: changed}
	modeChanged := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		runPeriodicReconcile(context.Background(), stub, []string{"default"}, 5*time.Millisecond,
			webhook.New("", nil, zerolog.Nop()), modeChanged, zerolog.Nop())
	}()

	select {
	case err := <-modeChanged:
		var got *firewall.ModeChangeError
		if !errors.As(err, &got) || got.Site != "default" {
			t.Fatalf("mode change error = %v, want the stub's", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no mode change reported")
	}
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("periodic reconcile kept running after a mode change")
	}
	if n := stub.reconciles.Load(); n != 0 {
		t.Errorf("reconciled %d times after the mode changed, want 0", n)
	}
}

func TestPeriodicReconcileRunsWithoutModeChange(t *testing.T) {
	stub := &modeChangeStub{}
	modeChanged := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		runPeriodicReconcile(ctx, stub, []string{"default"}, 5*time.Millisecond,
			webhook.New("", nil, zerolog.Nop()), modeChanged, zerolog.Nop())
	}()

	deadline := time.Now().Add(5 * time.Second)
	for stub.reconciles.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-finished
	if n := stub.reconciles.Load(); n < 2 {
		t.Fatalf("reconciled %d times, want at least 2", n)
	}
	select {
	case err := <-modeChanged:
		t.Fatalf("unexpected mode change: %v", err)
	default:
	}
}

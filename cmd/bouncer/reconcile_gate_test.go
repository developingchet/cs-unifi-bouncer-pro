package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestGateReconciles(t *testing.T) {
	tests := []struct {
		name      string
		synced    bool
		bans      int
		countErr  error
		wantStart int32
	}{
		{name: "first batch arrives", synced: true, wantStart: 1},
		{name: "first batch and fallback both fire", synced: true, bans: 5, wantStart: 1},
		{name: "no batch, intact database", bans: 5, wantStart: 1},
		{name: "no batch, empty database", bans: 0, wantStart: 0},
		{name: "no batch, unreadable database", countErr: errors.New("io"), wantStart: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var starts atomic.Int32
			var synced func()
			onSynced := func(fn func()) { synced = fn }
			count := func() (int, error) { return tt.bans, tt.countErr }
			gateReconciles(ctx, onSynced, count, 20*time.Millisecond, func() { starts.Add(1) }, zerolog.Nop())
			if tt.synced {
				synced()
			}
			time.Sleep(100 * time.Millisecond)
			if got := starts.Load(); got != tt.wantStart {
				t.Fatalf("reconcile started %d times, want %d", got, tt.wantStart)
			}
		})
	}
}

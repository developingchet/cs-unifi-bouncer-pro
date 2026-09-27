package main

import (
	"context"
	"errors"
	"testing"

	"github.com/rs/zerolog"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/firewall"
)

type repairStub struct {
	firewall.Manager
	err error
}

func (r repairStub) RepairInfrastructure(context.Context, []string) error { return r.err }
func (r repairStub) ZoneManager() *firewall.ZoneManager                   { return nil }

func TestRepairAndSyncWhitelistReportsFailure(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		cancel   bool
		wantFail bool
	}{
		{"repaired", nil, false, false},
		{"controller error stops the daemon", errors.New("list zone policies: HTTP 500"), false, true},
		{"shutdown during the repair", context.Canceled, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tt.cancel {
				cancel()
			}
			failed := make(chan error, 1)
			repairAndSyncWhitelist(ctx, &config.Config{}, nil, repairStub{err: tt.err}, nil, failed, zerolog.Nop())
			select {
			case err := <-failed:
				if !tt.wantFail {
					t.Fatalf("unexpected failure: %v", err)
				}
				if !errors.Is(err, tt.err) {
					t.Errorf("failure %v does not wrap %v", err, tt.err)
				}
			default:
				if tt.wantFail {
					t.Fatal("repair error was not reported")
				}
			}
		})
	}
}

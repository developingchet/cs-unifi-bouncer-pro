package firewall

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
)

// TestRepairInfrastructureDuringSyncs runs the startup repair while bans are
// applied, synced and reconciled, as the daemon does once the stream starts.
// Every shard must end up with exactly one rule or policy per scope.
func TestRepairInfrastructureDuringSyncs(t *testing.T) {
	for _, mode := range []string{"legacy", "zone"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			cfg := defaultManagerConfig()
			cfg.FirewallMode = mode
			if mode == "zone" {
				cfg.ZoneCfg.ZonePairs = []config.ZonePair{{Src: "wan", Dst: "lan"}}
			}
			mgr, ctrl, store := newTestManager(t, cfg)
			sites := []string{testSite}
			if err := mgr.LoadInfrastructure(ctx, sites); err != nil {
				t.Fatalf("LoadInfrastructure: %v", err)
			}

			var wg sync.WaitGroup
			errs := make(chan error, 64)
			for i := 0; i < 3; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if err := mgr.RepairInfrastructure(ctx, sites); err != nil {
						errs <- fmt.Errorf("RepairInfrastructure: %w", err)
					}
				}()
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < 20; i++ {
					ip := fmt.Sprintf("198.51.100.%d", i+1)
					// Reconcile removes controller IPs the store does not hold,
					// so each ban is recorded first, as the daemon does.
					if err := store.BanRecord(ip, time.Time{}, false); err != nil {
						errs <- fmt.Errorf("BanRecord: %w", err)
						return
					}
					if err := mgr.ApplyBan(ctx, testSite, ip, false); err != nil {
						errs <- fmt.Errorf("ApplyBan: %w", err)
						return
					}
					if err := mgr.SyncDirty(ctx, sites); err != nil {
						errs <- fmt.Errorf("SyncDirty: %w", err)
						return
					}
				}
			}()
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < 5; i++ {
					if _, err := mgr.Reconcile(ctx, sites); err != nil {
						errs <- fmt.Errorf("Reconcile: %w", err)
						return
					}
				}
			}()
			wg.Wait()
			close(errs)
			for err := range errs {
				t.Error(err)
			}

			if err := mgr.SyncDirty(ctx, sites); err != nil {
				t.Fatalf("final SyncDirty: %v", err)
			}
			seen := map[string]int{}
			if mode == "legacy" {
				rules, err := ctrl.ListFirewallRules(ctx, testSite)
				if err != nil {
					t.Fatal(err)
				}
				for _, r := range rules {
					seen[r.Name]++
				}
			} else {
				policies, err := ctrl.ListZonePolicies(ctx, testSite)
				if err != nil {
					t.Fatal(err)
				}
				for _, p := range policies {
					seen[p.Name]++
				}
			}
			if len(seen) == 0 {
				t.Fatal("no rule or policy was provisioned for the banned shard")
			}
			for name, n := range seen {
				if n != 1 {
					t.Errorf("%s exists %d times, want 1", name, n)
				}
			}
		})
	}
}

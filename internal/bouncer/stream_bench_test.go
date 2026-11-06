package bouncer

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/banstate"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/rs/zerolog"
)

// banBlock returns a stream block of n new ban decisions with IDs from
// firstID, each for its own public address.
func banBlock(firstID, n int) *models.DecisionsStreamResponse {
	block := &models.DecisionsStreamResponse{}
	for i := range n {
		id := firstID + i
		action, scope, origin, scenario, duration := "ban", "ip", "crowdsec", "ssh-bf", "4h"
		value := fmt.Sprintf("45.%d.%d.%d", id>>16&0xff, id>>8&0xff, id&0xff)
		block.New = append(block.New, &models.Decision{
			ID: int64(id), Type: &action, Scope: &scope, Value: &value,
			Origin: &origin, Scenario: &scenario, Duration: &duration,
		})
	}
	return block
}

// BenchmarkDecisionBlock applies stream blocks of new bans to a bbolt ban
// database, the store work the stream does for a burst of decisions.
func BenchmarkDecisionBlock(b *testing.B) {
	const blockSize = 500
	store, err := storage.NewBboltStore(b.TempDir(), zerolog.Nop(), 0)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = store.Close() })
	cfg := &config.Config{UnifiSites: []string{"default"}, BanTTL: 24 * time.Hour}
	fwMgr := &mockFirewallManager{}
	bnc, err := New(cfg, testutil.NewMockController(), store, fwMgr,
		banstate.New(store, fwMgr, cfg.UnifiSites, false), nopRecorder{}, zerolog.Nop())
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	next := 1
	for b.Loop() {
		bnc.handleDecisionBlock(ctx, banBlock(next, blockSize), "stream")
		next += blockSize
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*blockSize), "ns/decision")
}

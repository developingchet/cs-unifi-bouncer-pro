package firewall

import (
	"context"
	"fmt"
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/rs/zerolog"
)

// BenchmarkShardManagerAdd_ProductionScale loads a production-sized ban list
// (about 165k IPv4 addresses in 10k-address shards), the in-memory work a
// cold start or a reconcile of a wiped state performs.
func BenchmarkShardManagerAdd_ProductionScale(b *testing.B) {
	const bans = 165_000
	ips := make([]string, bans)
	for i := range ips {
		ips[i] = fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff)
	}
	ctx := context.Background()
	for b.Loop() {
		sm := NewShardManager("bench", false, 10_000, zoneTestNamerB(b), testutil.NewMockController(), testutil.NewMockStore(), zerolog.Nop(), 0, nil, false, "zone")
		for _, ip := range ips {
			if _, _, err := sm.Add(ctx, ip); err != nil {
				b.Fatal(err)
			}
		}
	}
}

func zoneTestNamerB(b *testing.B) *Namer {
	b.Helper()
	n, err := NewNamer("crowdsec-block-{{.Family}}-{{.Index}}", "crowdsec-drop-{{.Family}}-{{.Index}}",
		"crowdsec-policy-{{.SrcZone}}-{{.DstZone}}-{{.Family}}-{{.Index}}")
	if err != nil {
		b.Fatal(err)
	}
	return n
}

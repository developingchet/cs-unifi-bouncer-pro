package banstate

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
)

func requests(n int) []ClaimRequest {
	reqs := make([]ClaimRequest, n)
	for i := range reqs {
		reqs[i] = ClaimRequest{IP: fmt.Sprintf("198.18.%d.%d", i/250, i%250+1)}
	}
	return reqs
}

func TestClaimMany(t *testing.T) {
	tests := []struct {
		name      string
		n         int
		preclaim  int
		banErr    error
		wantAdded int
		wantBans  int
		wantErr   string
	}{
		{name: "new addresses across chunks", n: claimChunkSize*2 + 7, wantAdded: claimChunkSize*2 + 7, wantBans: claimChunkSize*2 + 7},
		{name: "already active addresses are only extended", n: 10, preclaim: 10, wantAdded: 0, wantBans: 10},
		{name: "firewall failure stays pending", n: 3, banErr: errors.New("controller down"), wantAdded: 0, wantBans: 3, wantErr: "3 of 3 addresses not applied"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := testutil.NewMockStore()
			fw := &recordingFirewall{}
			m := New(store, fw, []string{"default"}, false)
			ctx := context.Background()
			reqs := requests(tt.n)
			for _, r := range reqs[:tt.preclaim] {
				if _, err := m.Claim(ctx, r.IP, false, "crowdsec:id:1", time.Now().Add(time.Hour)); err != nil {
					t.Fatal(err)
				}
			}
			fw.banError = tt.banErr

			added, err := m.ClaimMany(ctx, reqs, "blocklist:feed", time.Now().Add(time.Hour))
			if tt.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			}
			if added != tt.wantAdded {
				t.Errorf("added = %d, want %d", added, tt.wantAdded)
			}
			if fw.bans != tt.wantBans {
				t.Errorf("firewall bans = %d, want %d", fw.bans, tt.wantBans)
			}
			for _, r := range reqs {
				entry, err := store.BanGet(r.IP)
				if err != nil || entry == nil {
					t.Fatalf("%s not recorded: %v", r.IP, err)
				}
				if _, ok := entry.Claims["blocklist:feed"]; !ok {
					t.Fatalf("%s missing feed claim: %+v", r.IP, entry.Claims)
				}
				if entry.Pending != (tt.banErr != nil) {
					t.Fatalf("%s pending = %v", r.IP, entry.Pending)
				}
			}
		})
	}
}

// ClaimBatch reports each claim's own outcome: claims on one address build
// on each other, a claim without a source fails alone, and the whole batch
// costs two writes.
func TestClaimBatch(t *testing.T) {
	store := testutil.NewMockStore()
	fw := &recordingFirewall{}
	m := New(store, fw, []string{"default"}, false)
	ctx := context.Background()
	expiry := time.Now().Add(time.Hour)
	if _, err := m.Claim(ctx, "203.0.113.9", false, "crowdsec:id:9", expiry); err != nil {
		t.Fatal(err)
	}
	store.ResetCalls()
	fw.bans = 0

	results, err := m.ClaimBatch(ctx, []Claim{
		{IP: "203.0.113.1", Source: "crowdsec:id:1", Expiry: expiry},
		{IP: "203.0.113.1", Source: "crowdsec:id:2", Expiry: expiry},
		{IP: "203.0.113.2", Source: "", Expiry: expiry},
		{IP: "203.0.113.9", Source: "crowdsec:id:3", Expiry: expiry},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 4 {
		t.Fatalf("results = %+v, want 4", results)
	}
	wantAdded := []bool{true, false, false, false}
	for i, r := range results {
		if r.Added != wantAdded[i] {
			t.Errorf("results[%d].Added = %v, want %v", i, r.Added, wantAdded[i])
		}
		if (r.Err != nil) != (i == 2) {
			t.Errorf("results[%d].Err = %v", i, r.Err)
		}
	}
	entry, err := store.BanGet("203.0.113.1")
	if err != nil || entry == nil || len(entry.Claims) != 2 || entry.Pending {
		t.Fatalf("203.0.113.1 = %+v, %v; want two claims, confirmed", entry, err)
	}
	if exists, _ := store.BanExists("203.0.113.2"); exists {
		t.Error("claim without a source was recorded")
	}
	if fw.bans != 1 {
		t.Errorf("firewall bans = %d, want 1", fw.bans)
	}
	if got := store.Calls("BanPutMany"); got != 2 {
		t.Errorf("BanPutMany calls = %d, want 2", got)
	}
}

// A failed record write ends the batch before any firewall change and
// leaves no result for the claims it covered.
func TestClaimBatchStoreFailure(t *testing.T) {
	store := testutil.NewMockStore()
	fw := &recordingFirewall{}
	m := New(store, fw, []string{"default"}, false)
	store.SetError("BanPutMany", errors.New("disk full"))
	results, err := m.ClaimBatch(context.Background(), []Claim{{IP: "203.0.113.1", Source: "crowdsec:id:1"}})
	if err == nil || len(results) != 0 {
		t.Fatalf("results = %+v, err = %v; want no results and an error", results, err)
	}
	if fw.bans != 0 {
		t.Errorf("firewall bans = %d, want 0", fw.bans)
	}
}

func TestClaimManyStopsOnCancel(t *testing.T) {
	store := testutil.NewMockStore()
	m := New(store, &recordingFirewall{}, []string{"default"}, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.ClaimMany(ctx, requests(3), "blocklist:feed", time.Now().Add(time.Hour)); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

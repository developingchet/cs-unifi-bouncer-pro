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

func TestClaimManyStopsOnCancel(t *testing.T) {
	store := testutil.NewMockStore()
	m := New(store, &recordingFirewall{}, []string{"default"}, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.ClaimMany(ctx, requests(3), "blocklist:feed", time.Now().Add(time.Hour)); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

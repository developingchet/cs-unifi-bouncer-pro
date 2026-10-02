package banstate

import (
	"context"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
)

func TestCountSource(t *testing.T) {
	store := testutil.NewMockStore()
	m := New(store, &recordingFirewall{}, []string{"default"}, false)
	ctx := context.Background()

	if _, err := m.ClaimMany(ctx, requests(5), "feed:a", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ClaimMany(ctx, requests(2), "feed:b", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ClaimMany(ctx, []ClaimRequest{{IP: "203.0.113.50"}}, "feed:a", time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}

	for source, want := range map[string]int{"feed:a": 5, "feed:b": 2, "feed:none": 0} {
		got, err := m.CountSource(source)
		if err != nil {
			t.Fatalf("CountSource(%q): %v", source, err)
		}
		if got != want {
			t.Errorf("CountSource(%q) = %d, want %d", source, got, want)
		}
	}
	if _, err := m.CountSource(""); err == nil {
		t.Error("CountSource accepted an empty source")
	}
}

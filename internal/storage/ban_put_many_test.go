package storage

import (
	"testing"
	"time"
)

func TestBanPutMany(t *testing.T) {
	s := newTestStore(t)
	expiry := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	entries := map[string]BanEntry{
		"198.51.100.1": {ExpiresAt: expiry, Claims: map[string]time.Time{"blocklist:feed": expiry}},
		"2001:db8::1":  {ExpiresAt: expiry, IPv6: true, Pending: true},
	}
	if err := s.BanPutMany(entries); err != nil {
		t.Fatalf("BanPutMany: %v", err)
	}
	if err := s.BanPutMany(nil); err != nil {
		t.Fatalf("BanPutMany(nil): %v", err)
	}
	for ip, want := range entries {
		got, err := s.BanGet(ip)
		if err != nil || got == nil {
			t.Fatalf("BanGet(%s): %v %v", ip, got, err)
		}
		if !got.ExpiresAt.Equal(want.ExpiresAt) || got.IPv6 != want.IPv6 || got.Pending != want.Pending {
			t.Errorf("%s = %+v, want %+v", ip, *got, want)
		}
	}
}

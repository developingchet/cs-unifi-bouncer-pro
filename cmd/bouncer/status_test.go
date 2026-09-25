package main

import (
	"reflect"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
)

func TestBanFilterApply(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	bans := map[string]storage.BanEntry{
		"192.0.2.1":    {RecordedAt: now.Add(-3 * time.Hour), ExpiresAt: now.Add(time.Hour)},
		"192.0.2.2":    {RecordedAt: now.Add(-1 * time.Hour), ExpiresAt: now.Add(48 * time.Hour)},
		"192.0.2.3":    {RecordedAt: now.Add(-2 * time.Hour)}, // never expires
		"198.51.100.9": {RecordedAt: now.Add(-5 * time.Hour), ExpiresAt: now.Add(-time.Minute)},
	}
	tests := []struct {
		name string
		f    banFilter
		want []string
	}{
		{name: "active, newest first", f: banFilter{}, want: []string{"192.0.2.2", "192.0.2.3", "192.0.2.1"}},
		{name: "sorted by IP", f: banFilter{sortBy: "ip"}, want: []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}},
		{name: "top 1", f: banFilter{top: 1}, want: []string{"192.0.2.2"}},
		{name: "expiring within 24h", f: banFilter{expiring: 24 * time.Hour}, want: []string{"192.0.2.1"}},
		{name: "expired only", f: banFilter{expired: true}, want: []string{"198.51.100.9"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			for _, r := range tt.f.apply(bans, now) {
				got = append(got, r.ip)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("apply = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFormatTime(t *testing.T) {
	if got := formatTime(time.Time{}, "never"); got != "never" {
		t.Errorf("zero time = %q", got)
	}
	ts := time.Date(2026, 1, 2, 3, 4, 5, 0, time.FixedZone("x", 3600))
	if got := formatTime(ts, "-"); got != "2026-01-02T02:04:05Z" {
		t.Errorf("formatTime = %q", got)
	}
}

package controller

import (
	"net/http"
	"testing"
	"time"
)

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		header string
		want   time.Duration
	}{
		{"missing", "", defaultRateLimitBackoff},
		{"seconds", "30", 30 * time.Second},
		{"zero clamps up", "0", minRateLimitBackoff},
		{"negative clamps up", "-5", minRateLimitBackoff},
		{"huge clamps down", "86400", maxRateLimitBackoff},
		{"http date", now.Add(45 * time.Second).Format(http.TimeFormat), 45 * time.Second},
		{"date in the past", now.Add(-time.Minute).Format(http.TimeFormat), minRateLimitBackoff},
		{"garbage", "soon", defaultRateLimitBackoff},
		{"fractional is not delay-seconds", "1.5", defaultRateLimitBackoff},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseRetryAfter(tt.header, now); got != tt.want {
				t.Fatalf("parseRetryAfter(%q) = %s, want %s", tt.header, got, tt.want)
			}
		})
	}
}

package controller

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	defaultRateLimitBackoff = 10 * time.Second
	minRateLimitBackoff     = 1 * time.Second
	// maxRateLimitBackoff stops one oversized Retry-After from pausing every
	// sync for hours; if the controller is still limiting, it says so again.
	maxRateLimitBackoff = 5 * time.Minute
)

// parseRetryAfter reads a Retry-After header in either RFC 9110 form:
// delay-seconds ("30") or an HTTP-date. A missing or unparseable header
// gives the default backoff; the result is clamped to [1s, 5m].
func parseRetryAfter(header string, now time.Time) time.Duration {
	header = strings.TrimSpace(header)
	wait := defaultRateLimitBackoff
	if secs, err := strconv.Atoi(header); err == nil {
		wait = time.Duration(secs) * time.Second
	} else if at, err := http.ParseTime(header); err == nil {
		wait = at.Sub(now)
	}
	return min(max(wait, minRateLimitBackoff), maxRateLimitBackoff)
}

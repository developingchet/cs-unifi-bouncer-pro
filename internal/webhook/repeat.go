package webhook

import (
	"maps"
	"sync"
	"time"
)

const (
	// repeatInterval is the shortest time between two deliveries of one
	// event about one subject. A controller that keeps refusing a shard or an
	// entry raises the same event at every retry; one notice an hour is
	// enough for an operator to act on.
	repeatInterval = time.Hour
	// maxRepeatSubjects bounds how many subjects the limiter remembers.
	// Once full, an event about a subject it does not know is dropped.
	maxRepeatSubjects = 1024
)

// repeatLimiter lets an event about a subject through at most once per
// interval and counts what it holds back.
type repeatLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	now      func() time.Time
	subjects map[string]*repeatState
}

type repeatState struct {
	sent       time.Time
	suppressed int
}

func newRepeatLimiter(interval time.Duration, now func() time.Time) *repeatLimiter {
	return &repeatLimiter{interval: interval, now: now, subjects: make(map[string]*repeatState)}
}

// allow reports whether the event for key may be delivered now and, if so,
// how many deliveries for key it held back since the last one.
func (l *repeatLimiter) allow(key string) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if state, ok := l.subjects[key]; ok {
		if now.Sub(state.sent) < l.interval {
			state.suppressed++
			return false, 0
		}
		held := state.suppressed
		l.subjects[key] = &repeatState{sent: now}
		return true, held
	}
	if len(l.subjects) >= maxRepeatSubjects {
		l.forgetExpired(now)
		if len(l.subjects) >= maxRepeatSubjects {
			return false, 0
		}
	}
	l.subjects[key] = &repeatState{sent: now}
	return true, 0
}

// forgetExpired drops subjects whose interval has passed. Callers hold l.mu.
func (l *repeatLimiter) forgetExpired(now time.Time) {
	maps.DeleteFunc(l.subjects, func(_ string, state *repeatState) bool {
		return now.Sub(state.sent) >= l.interval
	})
}

// FireLimited queues event like Fire, but at most once per hour for one
// subject (a shard, a ban entry, a sync). A later delivery for the subject
// carries "suppressed" in its detail: how many were held back since the
// previous one. detail is not modified.
func (n *Notifier) FireLimited(event, subject string, detail map[string]any) {
	if !n.wants(event) {
		return
	}
	ok, suppressed := n.repeats.allow(event + "\x00" + subject)
	if !ok {
		return
	}
	out := make(map[string]any, len(detail)+1)
	maps.Copy(out, detail)
	if suppressed > 0 {
		out["suppressed"] = suppressed
	}
	var payload any
	if len(out) > 0 {
		payload = out
	}
	n.enqueue(event, payload)
}

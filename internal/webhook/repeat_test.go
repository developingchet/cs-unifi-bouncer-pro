package webhook

import (
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// fakeClock is a settable time source.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func newLimitedNotifier(t *testing.T, url string, allowed []string) (*Notifier, *fakeClock) {
	t.Helper()
	clock := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	n := New(url, allowed, zerolog.Nop())
	n.repeats = newRepeatLimiter(time.Hour, clock.now)
	return n, clock
}

func TestFireLimited_OneDeliveryPerSubjectPerInterval(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	n, clock := newLimitedNotifier(t, srv.URL, nil)

	fireAndStop(t, n, func() {
		for i := 0; i < 5; i++ {
			n.FireLimited(EventShardCreateFailed, "default/crowdsec-block-v4-1", map[string]any{"attempt": i})
		}
		n.FireLimited(EventShardCreateFailed, "default/crowdsec-block-v4-2", nil)
		n.FireLimited(EventBanEntryRefused, "default/crowdsec-block-v4-1", nil)
		clock.t = clock.t.Add(time.Hour)
		n.FireLimited(EventShardCreateFailed, "default/crowdsec-block-v4-1", map[string]any{"attempt": 5})
	})

	got := rec.events(t)
	if len(got) != 4 {
		t.Fatalf("delivered %d events, want 4: %+v", len(got), got)
	}
	first := got[0].Detail.(map[string]any)
	if _, ok := first["suppressed"]; ok || first["attempt"] != float64(0) {
		t.Errorf("first delivery detail = %v, want attempt 0 without suppressed", first)
	}
	if got[1].Detail != nil {
		t.Errorf("second subject detail = %v, want none", got[1].Detail)
	}
	if got[2].Event != EventBanEntryRefused {
		t.Errorf("another event for the same subject was held back: %+v", got[2])
	}
	last := got[3].Detail.(map[string]any)
	if last["suppressed"] != float64(4) || last["attempt"] != float64(5) {
		t.Errorf("delivery after the interval detail = %v, want attempt 5 and suppressed 4", last)
	}
}

func TestFireLimited_DoesNotModifyDetail(t *testing.T) {
	n, clock := newLimitedNotifier(t, "http://127.0.0.1:1", nil)
	n.FireLimited(EventShardCreateFailed, "s", nil)
	n.FireLimited(EventShardCreateFailed, "s", nil)
	clock.t = clock.t.Add(time.Hour)
	detail := map[string]any{"site": "default"}
	n.FireLimited(EventShardCreateFailed, "s", detail)
	if len(detail) != 1 {
		t.Fatalf("caller's detail was modified: %v", detail)
	}
}

func TestFireLimited_RespectsEventFilter(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	n, _ := newLimitedNotifier(t, srv.URL, []string{EventCircuitBreakerOpen})
	fireAndStop(t, n, func() { n.FireLimited(EventBanEntryRefused, "x", nil) })
	if got := rec.events(t); len(got) != 0 {
		t.Fatalf("filtered event delivered: %+v", got)
	}
	// A filtered event must not use up the subject's allowance either.
	if len(n.repeats.subjects) != 0 {
		t.Fatalf("filtered event tracked: %v", n.repeats.subjects)
	}
}

func TestRepeatLimiter_BoundsSubjects(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	l := newRepeatLimiter(time.Hour, clock.now)
	for i := 0; i < maxRepeatSubjects; i++ {
		if ok, _ := l.allow(strconv.Itoa(i)); !ok {
			t.Fatalf("subject %d refused below the bound", i)
		}
	}
	if ok, _ := l.allow("one too many"); ok {
		t.Fatal("subject beyond the bound allowed while every other is in its interval")
	}
	clock.t = clock.t.Add(time.Hour)
	if ok, _ := l.allow("one too many"); !ok {
		t.Fatal("expired subjects were not forgotten")
	}
	if len(l.subjects) != 1 {
		t.Fatalf("tracked subjects = %d, want 1 after expiry", len(l.subjects))
	}
}

func TestNilNotifierIsSilent(t *testing.T) {
	var n *Notifier
	n.Fire(EventCircuitBreakerOpen, nil)
	n.FireLimited(EventShardCreateFailed, "s", nil)
}

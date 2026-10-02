package firewall

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
)

var errBreakerOpen = errors.New("sync deferred: controller circuit breaker open")

func errRateLimited(until time.Time) error {
	return fmt.Errorf("sync deferred by controller rate limit until %s", until.Format(time.RFC3339))
}

// admitWrites is checked before a pass that writes to the controller. It
// refuses while a rate-limit window is open or the circuit breaker is open.
// Once the breaker's reset interval has elapsed it admits the pass as the
// half-open probe, which must end in settleProbe.
func (m *managerImpl) admitWrites() error {
	if limited, until := m.isRateLimited(); limited {
		return errRateLimited(until)
	}
	if !m.cb.allow() {
		return errBreakerOpen
	}
	return nil
}

// writesPaused reports whether a pass in progress has to stop writing because
// a rate-limit window has opened or the breaker has tripped. It never starts
// a probe, so it can be asked between writes.
func (m *managerImpl) writesPaused() error {
	if limited, until := m.isRateLimited(); limited {
		return errRateLimited(until)
	}
	if m.cb.isOpen() {
		return errBreakerOpen
	}
	return nil
}

// settleProbe gives a half-open breaker a verdict once a pass that may have
// been its probe is over. A shard write that fails with a rate limit, a
// refused request or a provisioning error reports nothing to the breaker, and
// a pass with nothing to write never reaches it, so without this the breaker
// would stay half-open and refuse every later pass.
//
// A pass that failed reopens the breaker for a full reset interval. A pass
// whose only failures are refused requests proves the controller is
// answering, so it closes the breaker; the affected shards keep failing on
// their own. A pass without errors is confirmed with a read. The returned
// errors are passErrs, plus the probe error when that read fails.
func (m *managerImpl) settleProbe(ctx context.Context, passErrs []error) []error {
	if !m.cb.isHalfOpen() {
		return passErrs
	}
	switch {
	case len(passErrs) == 0:
		if err := m.ctrl.Ping(ctx); err != nil {
			m.reopenBreaker()
			return append(passErrs, fmt.Errorf("controller circuit breaker probe: %w", err))
		}
		m.recordControllerSuccess()
	case onlyRefusedRequests(passErrs):
		m.recordControllerSuccess()
	default:
		m.reopenBreaker()
	}
	return passErrs
}

func (m *managerImpl) reopenBreaker() {
	if m.cb.reopen() {
		m.log.Warn().Dur("retry_in", m.cb.resetAfter).
			Msg("circuit breaker probe failed: controller still unavailable")
	}
}

// noteRateLimit opens a rate-limit window when err carries a 429, for
// requests that do not report it through a shard write.
func (m *managerImpl) noteRateLimit(err error) {
	var rl *controller.ErrRateLimit
	if errors.As(err, &rl) {
		m.setRateLimitUntil(time.Now().Add(rl.RetryAfter))
	}
}

// onlyRefusedRequests reports whether every error is an HTTP 400 refusal.
func onlyRefusedRequests(errs []error) bool {
	for _, err := range errs {
		var bad *controller.ErrBadRequest
		if !errors.As(err, &bad) {
			return false
		}
	}
	return true
}

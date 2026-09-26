package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/logger"
	"github.com/rs/zerolog"
)

const (
	// queueSize bounds how many events wait for delivery. Events are rare
	// (circuit breaker transitions, reconcile drift), so a full queue means
	// the endpoint is stuck and dropping is preferable to blocking callers.
	queueSize = 64
	// requestTimeout bounds a single delivery.
	requestTimeout = 5 * time.Second
	// drainBudget bounds delivery of queued events after shutdown begins.
	drainBudget = 5 * time.Second
)

// Event names, the values WEBHOOK_EVENTS accepts.
const (
	EventCircuitBreakerOpen  = "circuit_breaker_open"
	EventCircuitBreakerClose = "circuit_breaker_close"
	EventReconcileDrift      = "reconcile_drift"
)

// Events lists every event the bouncer fires.
var Events = []string{EventCircuitBreakerOpen, EventCircuitBreakerClose, EventReconcileDrift}

// Event is the JSON payload sent to the webhook endpoint.
type Event struct {
	Event     string    `json:"event"`
	Timestamp time.Time `json:"timestamp"`
	Detail    any       `json:"detail,omitempty"`
}

// Notifier sends webhook notifications for configured events.
// It is a no-op when the URL is empty or the event is not in the allowed set.
// Fire only enqueues; Run performs delivery so callers (circuit breaker
// callbacks, the reconcile loop) never wait on a slow endpoint.
type Notifier struct {
	url     string
	display string              // host only: webhook paths often embed tokens
	events  map[string]struct{} // allowed event names; nil = all
	queue   chan Event
	client  *http.Client
	log     zerolog.Logger
}

// New creates a Notifier. If url is empty, all calls to Fire are no-ops.
// events is the list of event names to deliver (empty = all events).
func New(url string, events []string, log zerolog.Logger) *Notifier {
	var allowed map[string]struct{}
	if len(events) > 0 {
		allowed = make(map[string]struct{}, len(events))
		for _, e := range events {
			allowed[e] = struct{}{}
		}
	}
	return &Notifier{
		url:     url,
		display: logger.SafeHost(url),
		events:  allowed,
		queue:   make(chan Event, queueSize),
		client:  &http.Client{Timeout: requestTimeout},
		log:     log,
	}
}

// Fire queues an event for delivery and returns immediately.
// If the URL is empty or the event name is not in the allowed set, it is a no-op.
// When the queue is full the event is dropped with a warning.
func (n *Notifier) Fire(event string, detail any) {
	if n.url == "" {
		return
	}
	if n.events != nil {
		if _, ok := n.events[event]; !ok {
			return
		}
	}
	ev := Event{Event: event, Timestamp: time.Now().UTC(), Detail: detail}
	select {
	case n.queue <- ev:
	default:
		n.log.Warn().Str("event", event).Str("host", n.display).Msg("webhook: queue full, event dropped")
	}
}

// Run delivers queued events until ctx is cancelled, then makes a bounded
// attempt to deliver whatever is still queued.
func (n *Notifier) Run(ctx context.Context) {
	if n.url == "" {
		return
	}
	for {
		select {
		case <-ctx.Done():
			n.drain()
			return
		case ev := <-n.queue:
			// Shutdown must not abort an in-flight event (a circuit breaker
			// alert is most useful exactly then); the client timeout bounds it.
			n.deliver(context.WithoutCancel(ctx), ev)
		}
	}
}

func (n *Notifier) drain() {
	ctx, cancel := context.WithTimeout(context.Background(), drainBudget)
	defer cancel()
	for {
		select {
		case ev := <-n.queue:
			n.deliver(ctx, ev)
		default:
			return
		}
	}
}

// deliver posts one event. Errors are logged and never returned.
func (n *Notifier) deliver(ctx context.Context, ev Event) {
	data, err := json.Marshal(ev)
	if err != nil {
		n.log.Warn().Err(err).Str("event", ev.Event).Msg("webhook: failed to marshal payload")
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(data))
	if err != nil {
		n.log.Warn().Err(logger.SafeURLError(err, n.display)).Str("event", ev.Event).Msg("webhook: failed to create request")
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		n.log.Warn().Err(logger.SafeURLError(err, n.display)).Str("event", ev.Event).Msg("webhook: delivery failed")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		n.log.Warn().Str("event", ev.Event).Str("host", n.display).
			Str("status", fmt.Sprintf("%d", resp.StatusCode)).
			Msg("webhook: server returned error status")
	}
}

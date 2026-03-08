package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog"
)

// Event is the JSON payload sent to the webhook endpoint.
type Event struct {
	Event     string    `json:"event"`
	Timestamp time.Time `json:"timestamp"`
	Detail    any       `json:"detail,omitempty"`
}

// Notifier sends webhook notifications for configured events.
// It is a no-op when WebhookURL is empty or the event is not in WebhookEvents.
type Notifier struct {
	url    string
	events map[string]struct{} // allowed event names; nil = all
	client *http.Client
	log    zerolog.Logger
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
		url:    url,
		events: allowed,
		client: &http.Client{Timeout: 5 * time.Second},
		log:    log,
	}
}

// Fire delivers an event to the configured webhook URL.
// If the URL is empty or the event name is not in the allowed set, it is a no-op.
// HTTP errors are logged as warnings and never returned.
func (n *Notifier) Fire(ctx context.Context, event string, detail any) {
	if n.url == "" {
		return
	}
	if n.events != nil {
		if _, ok := n.events[event]; !ok {
			return
		}
	}

	payload := Event{
		Event:     event,
		Timestamp: time.Now().UTC(),
		Detail:    detail,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		n.log.Warn().Err(err).Str("event", event).Msg("webhook: failed to marshal payload")
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(data))
	if err != nil {
		n.log.Warn().Err(err).Str("event", event).Msg("webhook: failed to create request")
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		n.log.Warn().Err(err).Str("event", event).Msg("webhook: delivery failed")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		n.log.Warn().Str("event", event).
			Str("status", fmt.Sprintf("%d", resp.StatusCode)).
			Msg("webhook: server returned error status")
	}
}

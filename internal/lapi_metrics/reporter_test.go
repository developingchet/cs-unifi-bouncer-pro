package lapi_metrics

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/capabilities"
	"github.com/rs/zerolog"
)

// newTestReporter constructs a Reporter for testing, pointing at the given httptest server.
func newTestReporter(t *testing.T, srv *httptest.Server, interval time.Duration) *Reporter {
	t.Helper()
	return NewReporter(srv.URL, "test-key", "1.2.3", interval, zerolog.Nop())
}

// payloadCapture holds a decoded remediation_components entry.
type payloadCapture struct {
	Type     string                 `json:"type"`
	Version  string                 `json:"version"`
	Os       map[string]interface{} `json:"os"`
	Features []interface{}          `json:"features"`
	Meta     map[string]interface{} `json:"meta"`
	Metrics  []metricSnapshot       `json:"metrics"`
}

type metricSnapshot struct {
	Name   string                 `json:"name"`
	Value  int64                  `json:"value"`
	Unit   string                 `json:"unit"`
	Labels map[string]interface{} `json:"labels,omitempty"`
}

// captureHandler records all POST requests to track payloads.
type captureHandler struct {
	mu       sync.Mutex
	requests []payloadCapture
}

func (ch *captureHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Decode the payload to extract remediation_components
	var envelope struct {
		RemediationComponents []payloadCapture `json:"remediation_components"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		http.Error(w, "unmarshal error", http.StatusBadRequest)
		return
	}

	ch.mu.Lock()
	ch.requests = append(ch.requests, envelope.RemediationComponents...)
	ch.mu.Unlock()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("{}"))
}

func (ch *captureHandler) lastPayload() *payloadCapture {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	if len(ch.requests) == 0 {
		return nil
	}
	return &ch.requests[len(ch.requests)-1]
}

func (ch *captureHandler) allPayloads() []payloadCapture {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	result := make([]payloadCapture, len(ch.requests))
	copy(result, ch.requests)
	return result
}

// TestNewReporter_IntervalClamping verifies interval clamping behavior.
func TestNewReporter_IntervalClamping(t *testing.T) {
	tests := []struct {
		name     string
		input    time.Duration
		expected time.Duration
	}{
		{
			name:     "5m clamped to 10m",
			input:    5 * time.Minute,
			expected: 10 * time.Minute,
		},
		{
			name:     "10m unchanged",
			input:    10 * time.Minute,
			expected: 10 * time.Minute,
		},
		{
			name:     "30m unchanged",
			input:    30 * time.Minute,
			expected: 30 * time.Minute,
		},
		{
			name:     "0 unchanged (disabled)",
			input:    0,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewReporter("http://localhost", "key", "1.0.0", tt.input, zerolog.Nop())
			if r.interval != tt.expected {
				t.Errorf("got interval %v, want %v", r.interval, tt.expected)
			}
		})
	}
}

// TestRecordBan_IncrementsCounters verifies that RecordBan increments both origin/type and processed counters.
func TestRecordBan_IncrementsCounters(t *testing.T) {
	ch := &captureHandler{}
	srv := httptest.NewServer(ch)
	defer srv.Close()

	r := newTestReporter(t, srv, 10*time.Minute)

	// Record bans
	r.RecordBan("CAPI", "ban")
	r.RecordBan("CAPI", "ban")
	r.RecordBan("CAPI", "ban")
	r.RecordBan("cscli", "ban")

	// Push to fake server
	if err := r.push(context.Background()); err != nil {
		t.Fatalf("push failed: %v", err)
	}

	payload := ch.lastPayload()
	if payload == nil {
		t.Fatal("no payload received")
	}

	// Find the metrics
	capiCount := int64(0)
	cscliCount := int64(0)
	processedCount := int64(0)

	for _, m := range payload.Metrics {
		switch m.Name {
		case "blocked":
			if m.Labels["origin"] == "CAPI" && m.Labels["remediation_type"] == "ban" {
				capiCount = m.Value
			}
			if m.Labels["origin"] == "cscli" && m.Labels["remediation_type"] == "ban" {
				cscliCount = m.Value
			}
		case "processed":
			processedCount = m.Value
		}
	}

	if capiCount != 3 {
		t.Errorf("CAPI ban count: got %d, want 3", capiCount)
	}
	if cscliCount != 1 {
		t.Errorf("cscli ban count: got %d, want 1", cscliCount)
	}
	if processedCount != 4 {
		t.Errorf("processed count: got %d, want 4", processedCount)
	}
}

// TestRecordDeletion_OnlyIncreasesProcessed verifies deletion only touches processed counter.
func TestRecordDeletion_OnlyIncreasesProcessed(t *testing.T) {
	ch := &captureHandler{}
	srv := httptest.NewServer(ch)
	defer srv.Close()

	r := newTestReporter(t, srv, 10*time.Minute)

	r.RecordDeletion()
	r.RecordDeletion()

	if err := r.push(context.Background()); err != nil {
		t.Fatalf("push failed: %v", err)
	}

	payload := ch.lastPayload()
	if payload == nil {
		t.Fatal("no payload received")
	}

	// Check no "blocked" entries exist
	processedCount := int64(0)
	for _, m := range payload.Metrics {
		if m.Name == "blocked" {
			t.Fatalf("unexpected blocked metric found: %v", m)
		}
		if m.Name == "processed" {
			processedCount = m.Value
		}
	}

	if processedCount != 2 {
		t.Errorf("processed count: got %d, want 2", processedCount)
	}
}

// TestPush_CountersResetAfterPush verifies counters reset after each push.
func TestPush_CountersResetAfterPush(t *testing.T) {
	ch := &captureHandler{}
	srv := httptest.NewServer(ch)
	defer srv.Close()

	r := newTestReporter(t, srv, 10*time.Minute)

	// First push
	r.RecordBan("CAPI", "ban")
	r.RecordBan("CAPI", "ban")
	if err := r.push(context.Background()); err != nil {
		t.Fatalf("first push failed: %v", err)
	}

	payload1 := ch.lastPayload()
	var firstProcessed int64
	for _, m := range payload1.Metrics {
		if m.Name == "processed" {
			firstProcessed = m.Value
			break
		}
	}
	if firstProcessed != 2 {
		t.Errorf("first push processed: got %d, want 2", firstProcessed)
	}

	// Second push with one more ban
	r.RecordBan("CAPI", "ban")
	if err := r.push(context.Background()); err != nil {
		t.Fatalf("second push failed: %v", err)
	}

	payload2 := ch.lastPayload()
	var secondProcessed int64
	for _, m := range payload2.Metrics {
		if m.Name == "processed" {
			secondProcessed = m.Value
			break
		}
	}
	if secondProcessed != 1 {
		t.Errorf("second push processed: got %d, want 1 (not cumulative)", secondProcessed)
	}
}

// TestPush_PayloadStructure verifies the exact JSON structure sent to the server.
func TestPush_PayloadStructure(t *testing.T) {
	ch := &captureHandler{}
	srv := httptest.NewServer(ch)
	defer srv.Close()

	r := newTestReporter(t, srv, 10*time.Minute)
	r.RecordBan("CAPI", "ban")
	r.RecordDeletion()

	if err := r.push(context.Background()); err != nil {
		t.Fatalf("push failed: %v", err)
	}

	payload := ch.lastPayload()
	if payload == nil {
		t.Fatal("no payload received")
	}

	// Check type
	if payload.Type != capabilities.BouncerType {
		t.Errorf("type: got %q, want %q", payload.Type, capabilities.BouncerType)
	}

	// Check version
	if payload.Version != "1.2.3" {
		t.Errorf("version: got %q, want %q", payload.Version, "1.2.3")
	}

	// Check os.name is non-empty
	osName, ok := payload.Os["name"]
	if !ok || osName == "" {
		t.Errorf("os.name missing or empty")
	}

	// Check features is empty array, not null
	if payload.Features == nil {
		t.Errorf("features is nil, want empty array")
	}
	if len(payload.Features) != 0 {
		t.Errorf("features length: got %d, want 0", len(payload.Features))
	}

	// Check meta fields
	meta := payload.Meta
	if meta == nil {
		t.Fatal("meta is nil")
	}

	// Extract and verify window_size_seconds as int64
	windowSizeRaw := meta["window_size_seconds"]
	var windowSize int64
	switch v := windowSizeRaw.(type) {
	case float64:
		windowSize = int64(v)
	case json.Number:
		i, _ := v.Int64()
		windowSize = i
	default:
		t.Fatalf("window_size_seconds has unexpected type %T", windowSizeRaw)
	}
	if windowSize != int64((10 * time.Minute).Seconds()) {
		t.Errorf("window_size_seconds: got %d, want %d", windowSize, int64((10 * time.Minute).Seconds()))
	}

	// Extract timestamps
	startupTS, ok := meta["utc_startup_timestamp"].(float64)
	if !ok {
		t.Errorf("utc_startup_timestamp missing or wrong type")
	}
	if startupTS <= 0 {
		t.Errorf("utc_startup_timestamp: got %v, want > 0", startupTS)
	}

	nowTS, ok := meta["utc_now_timestamp"].(float64)
	if !ok {
		t.Errorf("utc_now_timestamp missing or wrong type")
	}
	if nowTS < startupTS {
		t.Errorf("utc_now_timestamp (%v) < utc_startup_timestamp (%v)", nowTS, startupTS)
	}

	// Check processed entry always present, even if not called
	var foundProcessed bool
	for _, m := range payload.Metrics {
		if m.Name == "processed" {
			foundProcessed = true
			if m.Value != 2 {
				t.Errorf("processed: got %d, want 2", m.Value)
			}
			break
		}
	}
	if !foundProcessed {
		t.Errorf("processed metric not found")
	}
}

// TestPush_UserAgentHeader verifies the User-Agent header.
func TestPush_UserAgentHeader(t *testing.T) {
	var capturedUserAgent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUserAgent = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{}"))
	}))
	defer srv.Close()

	r := newTestReporter(t, srv, 10*time.Minute)
	if err := r.push(context.Background()); err != nil {
		t.Fatalf("push failed: %v", err)
	}

	expected := "crowdsec-unifi-bouncer/v1.2.3"
	if capturedUserAgent != expected {
		t.Errorf("User-Agent: got %q, want %q", capturedUserAgent, expected)
	}
}

// TestPush_APIKeyHeader verifies the X-Api-Key header.
func TestPush_APIKeyHeader(t *testing.T) {
	var capturedKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedKey = r.Header.Get("X-Api-Key")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{}"))
	}))
	defer srv.Close()

	r := newTestReporter(t, srv, 10*time.Minute)
	if err := r.push(context.Background()); err != nil {
		t.Fatalf("push failed: %v", err)
	}

	if capturedKey != "test-key" {
		t.Errorf("X-Api-Key: got %q, want %q", capturedKey, "test-key")
	}
}

// TestPush_Non2xxLogsWarn verifies non-2xx responses don't return an error, just warn.
func TestPush_Non2xxLogsWarn(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	r := newTestReporter(t, srv, 10*time.Minute)
	r.RecordBan("CAPI", "ban")

	// Should not return an error
	err := r.push(context.Background())
	if err != nil {
		t.Errorf("push with 500 returned error: %v, want nil", err)
	}
}

// TestRun_DisabledWhenIntervalZero verifies Run returns immediately when interval is 0.
func TestRun_DisabledWhenIntervalZero(t *testing.T) {
	ch := &captureHandler{}
	srv := httptest.NewServer(ch)
	defer srv.Close()

	r := newTestReporter(t, srv, 0)
	r.RecordBan("CAPI", "ban")

	// Use a channel to detect if Run hangs
	done := make(chan bool, 1)
	go func() {
		r.Run(context.Background())
		done <- true
	}()

	// Should complete within 100ms (not hang)
	select {
	case <-done:
		// OK
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Run(ctx) did not return immediately when interval=0")
	}

	// No requests should have been sent
	if len(ch.allPayloads()) > 0 {
		t.Errorf("Run with interval=0 sent requests, want none")
	}
}

// TestRun_PushesOnTick verifies Run pushes metrics periodically.
func TestRun_PushesOnTick(t *testing.T) {
	ch := &captureHandler{}
	srv := httptest.NewServer(ch)
	defer srv.Close()

	r := newTestReporter(t, srv, 30*time.Minute)
	// Override interval for test to make it very short and avoid the clamp
	r.interval = 50 * time.Millisecond

	r.RecordBan("CAPI", "ban")

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// Start Run in a goroutine
	done := make(chan error, 1)
	go func() {
		r.Run(ctx)
		done <- nil
	}()

	// Wait for Run to finish or timeout
	select {
	case <-done:
	case <-time.After(600 * time.Millisecond):
		t.Fatal("Run did not return within timeout")
	}

	// Should have received at least one push (plus the final push on context done)
	payloads := ch.allPayloads()
	if len(payloads) < 1 {
		t.Fatalf("expected at least 1 push, got %d", len(payloads))
	}

	// Verify metrics in the first payload
	foundBan := false
	for _, m := range payloads[0].Metrics {
		if m.Name == "blocked" && m.Labels["origin"] == "CAPI" && m.Labels["remediation_type"] == "ban" {
			foundBan = true
			if m.Value != 1 {
				t.Errorf("first push CAPI ban count: got %d, want 1", m.Value)
			}
			break
		}
	}
	if !foundBan {
		t.Errorf("CAPI ban metric not found in first push")
	}
}

// TestConcurrentRecordBan verifies concurrent recording doesn't race and counts correctly.
func TestConcurrentRecordBan(t *testing.T) {
	ch := &captureHandler{}
	srv := httptest.NewServer(ch)
	defer srv.Close()

	r := newTestReporter(t, srv, 10*time.Minute)

	// Spin up 50 goroutines, each calling RecordBan 100 times
	const numGoroutines = 50
	const numCalls = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < numCalls; j++ {
				r.RecordBan("CAPI", "ban")
			}
		}()
	}

	wg.Wait()

	// Push and verify counts
	if err := r.push(context.Background()); err != nil {
		t.Fatalf("push failed: %v", err)
	}

	payload := ch.lastPayload()
	if payload == nil {
		t.Fatal("no payload received")
	}

	expectedTotal := int64(numGoroutines * numCalls)
	var bannedCount, processedCount int64

	for _, m := range payload.Metrics {
		if m.Name == "blocked" && m.Labels["origin"] == "CAPI" && m.Labels["remediation_type"] == "ban" {
			bannedCount = m.Value
		}
		if m.Name == "processed" {
			processedCount = m.Value
		}
	}

	if bannedCount != expectedTotal {
		t.Errorf("blocked[CAPI][ban]: got %d, want %d", bannedCount, expectedTotal)
	}
	if processedCount != expectedTotal {
		t.Errorf("processed: got %d, want %d", processedCount, expectedTotal)
	}
}

package controller

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

// TestHasFeature_ZoneFirewall_Supported verifies that hasFeature returns true
// when the zone endpoint responds with HTTP 200.
func TestHasFeature_ZoneFirewall_Supported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"data":[],"meta":{"rc":"ok"}}`)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	c.featureCache = make(map[string]map[string]bool)

	got, err := hasFeature(context.Background(), c, "default", FeatureZoneBasedFirewall)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !got {
		t.Error("expected hasFeature to return true when server responds 200")
	}
}

// TestHasFeature_ZoneFirewall_NotSupported verifies that hasFeature returns
// false when the zone endpoint responds with HTTP 404 (ErrNotFound).
func TestHasFeature_ZoneFirewall_NotSupported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	c.featureCache = make(map[string]map[string]bool)

	got, err := hasFeature(context.Background(), c, "default", FeatureZoneBasedFirewall)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if got {
		t.Error("expected hasFeature to return false when server responds 404")
	}
}

// TestHasFeature_Cached verifies that a second call for the same (site, feature)
// does not make another HTTP request — the result is served from the cache.
func TestHasFeature_Cached(t *testing.T) {
	var callCount int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"data":[],"meta":{"rc":"ok"}}`)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	c.featureCache = make(map[string]map[string]bool)

	// First call — should hit the server.
	got1, err := hasFeature(context.Background(), c, "default", FeatureZoneBasedFirewall)
	if err != nil {
		t.Fatalf("first call: expected no error, got: %v", err)
	}

	// Second call — should be served from cache.
	got2, err := hasFeature(context.Background(), c, "default", FeatureZoneBasedFirewall)
	if err != nil {
		t.Fatalf("second call: expected no error, got: %v", err)
	}

	if got1 != got2 {
		t.Errorf("cache returned different value: first=%v, second=%v", got1, got2)
	}

	count := atomic.LoadInt32(&callCount)
	if count != 1 {
		t.Errorf("expected exactly 1 HTTP call (cached), got %d", count)
	}
}

// TestHasFeature_CacheSeparatePerSite verifies that cached results for site "a"
// do not prevent a fresh HTTP probe for site "b".
func TestHasFeature_CacheSeparatePerSite(t *testing.T) {
	var callCount int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"data":[],"meta":{"rc":"ok"}}`)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	c.featureCache = make(map[string]map[string]bool)

	// Probe site "a".
	_, err := hasFeature(context.Background(), c, "a", FeatureZoneBasedFirewall)
	if err != nil {
		t.Fatalf("site a: expected no error, got: %v", err)
	}

	// Probe site "b" — cache for "a" must not block a new probe.
	_, err = hasFeature(context.Background(), c, "b", FeatureZoneBasedFirewall)
	if err != nil {
		t.Fatalf("site b: expected no error, got: %v", err)
	}

	count := atomic.LoadInt32(&callCount)
	if count != 2 {
		t.Errorf("expected 2 HTTP calls (one per site), got %d", count)
	}
}

// TestHasFeature_CacheConcurrent verifies that 20 goroutines calling hasFeature
// simultaneously all receive consistent results without data races.
func TestHasFeature_CacheConcurrent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"data":[],"meta":{"rc":"ok"}}`)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	c.featureCache = make(map[string]map[string]bool)

	const goroutines = 20
	results := make([]bool, goroutines)
	errs := make([]error, goroutines)
	var wg sync.WaitGroup

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx], errs[idx] = hasFeature(context.Background(), c, "concurrent-site", FeatureZoneBasedFirewall)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: unexpected error: %v", i, err)
		}
	}
	// All goroutines must have received the same result.
	for i, r := range results {
		if r != results[0] {
			t.Errorf("goroutine %d: inconsistent result: got %v, want %v", i, r, results[0])
		}
	}
}

// TestHasFeature_Unknown verifies that an unrecognised feature name returns
// an error immediately without making any HTTP request.
func TestHasFeature_Unknown(t *testing.T) {
	var callCount int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	c.featureCache = make(map[string]map[string]bool)

	_, err := hasFeature(context.Background(), c, "default", "UNKNOWN_FEATURE_XYZ")
	if err == nil {
		t.Fatal("expected error for unknown feature, got nil")
	}

	count := atomic.LoadInt32(&callCount)
	if count != 0 {
		t.Errorf("expected 0 HTTP calls for unknown feature, got %d", count)
	}
}

// TestHasFeature_UnexpectedResponse verifies that when the server returns HTTP 200
// with an invalid (non-JSON) body, hasFeature still returns true (assumes supported).
func TestHasFeature_UnexpectedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		// Invalid JSON body — should trigger the decode-error path in detectZoneFirewall.
		_, _ = fmt.Fprint(w, `not valid json {{{`)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	c.featureCache = make(map[string]map[string]bool)

	got, err := hasFeature(context.Background(), c, "default", FeatureZoneBasedFirewall)
	if err != nil {
		t.Fatalf("expected no error on invalid JSON body, got: %v", err)
	}
	if !got {
		t.Error("expected hasFeature to return true when JSON decode fails (assume supported)")
	}
}

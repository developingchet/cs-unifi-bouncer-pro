package controller

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// Fake UUIDs used throughout these tests.
// Using clearly non-real values to avoid confusion with live controller data.
const (
	testSiteUUID     = "aaaaaaaa-0000-4000-8000-aaaaaaaaaaaa"
	testZoneInternal = "bbbbbbbb-0000-4000-8000-bbbbbbbbbbbb"
	testZoneExternal = "cccccccc-0000-4000-8000-cccccccccccc"
)

// setSiteIDCache pre-populates the siteIDCache on a test client so that
// getSiteID doesn't need to make HTTP calls during feature-detection tests.
func setSiteIDCache(c *unifiClient, siteName, siteID string) {
	c.cacheMu.Lock()
	c.siteIDCache[siteName] = siteID
	c.cacheMu.Unlock()
}

// zonesEndpointPrefix returns the URL path prefix for the integration v1 zones endpoint.
func zonesEndpointPrefix(siteID string) string {
	return fmt.Sprintf("/proxy/network/integration/v1/sites/%s/firewall/zones", siteID)
}

// TestHasFeature_ZoneFirewall_Supported verifies that hasFeature returns true
// when the zone endpoint responds with HTTP 200.
func TestHasFeature_ZoneFirewall_Supported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"offset":0,"limit":1,"count":0,"totalCount":0,"data":[]}`)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	setSiteIDCache(c, "default", testSiteUUID)

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
	setSiteIDCache(c, "default", testSiteUUID)

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
		_, _ = fmt.Fprint(w, `{"offset":0,"limit":1,"count":0,"totalCount":0,"data":[]}`)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	setSiteIDCache(c, "default", testSiteUUID)

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
		_, _ = fmt.Fprint(w, `{"offset":0,"limit":1,"count":0,"totalCount":0,"data":[]}`)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	setSiteIDCache(c, "a", testSiteUUID)
	setSiteIDCache(c, "b", testSiteUUID)

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
		_, _ = fmt.Fprint(w, `{"offset":0,"limit":1,"count":0,"totalCount":0,"data":[]}`)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	setSiteIDCache(c, "concurrent-site", testSiteUUID)

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
// with a non-HTML body, hasFeature still returns true (assumes supported).
func TestHasFeature_UnexpectedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		// Non-JSON, non-HTML body — first byte is 'n', not '<'.
		_, _ = fmt.Fprint(w, `not valid json {{{`)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	setSiteIDCache(c, "default", testSiteUUID)

	got, err := hasFeature(context.Background(), c, "default", FeatureZoneBasedFirewall)
	if err != nil {
		t.Fatalf("expected no error on non-JSON body, got: %v", err)
	}
	if !got {
		t.Error("expected hasFeature to return true when body is not HTML")
	}
}

// TestDetectZoneFirewall_HTMLResponse verifies that an HTML response (proxy
// fallback page) causes detectZoneFirewall to return false.
func TestDetectZoneFirewall_HTMLResponse(t *testing.T) {
	prefix := zonesEndpointPrefix(testSiteUUID)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, prefix) {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "<html><body>SPA</body></html>")
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	setSiteIDCache(c, "default", testSiteUUID)

	supported, err := detectZoneFirewall(context.Background(), c, "default")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if supported {
		t.Fatal("expected supported=false for HTML response")
	}
}

// TestGetZoneID_MongoObjectID verifies that a 24-char hex MongoDB ObjectID is
// passed through directly without any HTTP calls.
func TestGetZoneID_MongoObjectID(t *testing.T) {
	c := newTestClient("https://example.invalid", "api-key")
	const zoneID = "67a8cc9efe6c6350dfa4dcc7"

	got, err := getZoneID(context.Background(), c, "default", zoneID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if got != zoneID {
		t.Fatalf("expected zone ID %q, got %q", zoneID, got)
	}
}

// TestGetZoneID_StandardUUID verifies that a standard 36-char UUID is passed
// through directly without any HTTP calls.
func TestGetZoneID_StandardUUID(t *testing.T) {
	c := newTestClient("https://example.invalid", "api-key")

	got, err := getZoneID(context.Background(), c, "default", testZoneInternal)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if got != testZoneInternal {
		t.Fatalf("expected zone ID %q, got %q", testZoneInternal, got)
	}
}

// TestGetZoneID_NameFails verifies that getZoneID returns an error when the
// firewall zones endpoint is unavailable (HTTP 404).
func TestGetZoneID_NameFails(t *testing.T) {
	prefix := zonesEndpointPrefix(testSiteUUID)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, prefix) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	setSiteIDCache(c, "default", testSiteUUID)

	_, err := getZoneID(context.Background(), c, "default", "Internal")
	if err == nil {
		t.Fatal("expected error when zone list endpoint returns 404")
	}
	if got := err.Error(); !strings.Contains(got, "firewall zones") {
		t.Fatalf("unexpected error message: %q", got)
	}
}

// TestGetZoneID_NameResolvedFromZoneList verifies that getZoneID resolves a zone
// name to its UUID via the integration v1 zones endpoint.
func TestGetZoneID_NameResolvedFromZoneList(t *testing.T) {
	const wantID = testZoneInternal
	prefix := zonesEndpointPrefix(testSiteUUID)

	zoneList := makeV1Page(
		apiFirewallZoneV1{ID: testZoneExternal, Name: "WAN"},
		apiFirewallZoneV1{ID: wantID, Name: "Internal"},
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, prefix) {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(zoneList)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	setSiteIDCache(c, "default", testSiteUUID)

	got, err := getZoneID(context.Background(), c, "default", "Internal")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if got != wantID {
		t.Fatalf("expected zone ID %q, got %q", wantID, got)
	}

	// Verify cache was populated.
	c.cacheMu.RLock()
	cached := c.zoneIDCache["default"]["Internal"]
	c.cacheMu.RUnlock()
	if cached != wantID {
		t.Errorf("cache entry for %q = %q, want %q", "Internal", cached, wantID)
	}
}

// TestGetZoneID_NameFails_ZoneNotInList verifies that getZoneID returns a
// descriptive error when the zone list is returned but doesn't contain the
// requested zone name.
func TestGetZoneID_NameFails_ZoneNotInList(t *testing.T) {
	prefix := zonesEndpointPrefix(testSiteUUID)

	zoneList := makeV1Page(
		apiFirewallZoneV1{ID: testZoneExternal, Name: "WAN"},
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, prefix) {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(zoneList)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, "api-key")
	setSiteIDCache(c, "default", testSiteUUID)

	_, err := getZoneID(context.Background(), c, "default", "Internal")
	if err == nil {
		t.Fatal("expected error when zone name is absent from zone list")
	}
	if got := err.Error(); !strings.Contains(got, "not found") || !strings.Contains(got, "ZONE_PAIRS") {
		t.Fatalf("unexpected error message: %q", got)
	}
}

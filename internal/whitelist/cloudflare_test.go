package whitelist

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFetchIPv4_ParsesLines(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("1.1.1.0/24\n2.2.2.0/24\n3.3.3.0/24\n"))
	}))
	defer server.Close()

	provider := NewCloudflareProvider(server.URL, "")
	cidrs, err := provider.FetchIPv4(context.Background())
	if err != nil {
		t.Fatalf("FetchIPv4: %v", err)
	}

	if len(cidrs) != 3 {
		t.Errorf("expected 3 CIDRs, got %d", len(cidrs))
	}
	if cidrs[0] != "1.1.1.0/24" {
		t.Errorf("expected first CIDR to be 1.1.1.0/24, got %s", cidrs[0])
	}
}

func TestFetchIPv4_IgnoresComments(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("# Cloudflare IPv4 CIDRs\n1.1.1.0/24\n# Another comment\n2.2.2.0/24\n"))
	}))
	defer server.Close()

	provider := NewCloudflareProvider(server.URL, "")
	cidrs, err := provider.FetchIPv4(context.Background())
	if err != nil {
		t.Fatalf("FetchIPv4: %v", err)
	}

	if len(cidrs) != 2 {
		t.Errorf("expected 2 CIDRs, got %d", len(cidrs))
	}
}

func TestFetchIPv4_EmptyLines(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("1.1.1.0/24\n\n2.2.2.0/24\n\n"))
	}))
	defer server.Close()

	provider := NewCloudflareProvider(server.URL, "")
	cidrs, err := provider.FetchIPv4(context.Background())
	if err != nil {
		t.Fatalf("FetchIPv4: %v", err)
	}

	if len(cidrs) != 2 {
		t.Errorf("expected 2 CIDRs, got %d", len(cidrs))
	}
}

func TestFetchIPv4_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	provider := NewCloudflareProvider(server.URL, "")
	_, err := provider.FetchIPv4(context.Background())
	if err == nil {
		t.Error("expected error for HTTP 500, got nil")
	}
	if !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("expected error to contain 'HTTP 500', got: %v", err)
	}
}

func TestFetchIPv6_ParsesLines(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("2001:db8::/32\n2001:db9::/32\n"))
	}))
	defer server.Close()

	provider := NewCloudflareProvider("http://example.com", server.URL)
	cidrs, err := provider.FetchIPv6(context.Background())
	if err != nil {
		t.Fatalf("FetchIPv6: %v", err)
	}

	if len(cidrs) != 2 {
		t.Errorf("expected 2 CIDRs, got %d", len(cidrs))
	}
	if cidrs[0] != "2001:db8::/32" {
		t.Errorf("expected first CIDR to be 2001:db8::/32, got %s", cidrs[0])
	}
}

func TestCloudflareProvider_Timeout(t *testing.T) {
	// Server that sleeps longer than the timeout
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	provider := NewCloudflareProvider(server.URL, "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := provider.FetchIPv4(ctx)
	if err == nil {
		t.Error("expected timeout error, got nil")
	}
}

func TestFetchIPv4_IgnoresEmptyLines(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("1.1.1.0/24\n\n2.2.2.0/24\n\n"))
	}))
	defer server.Close()

	provider := NewCloudflareProvider(server.URL, "")
	cidrs, err := provider.FetchIPv4(context.Background())
	if err != nil {
		t.Fatalf("FetchIPv4: %v", err)
	}

	if len(cidrs) != 2 {
		t.Errorf("expected 2 CIDRs, got %d", len(cidrs))
	}
}

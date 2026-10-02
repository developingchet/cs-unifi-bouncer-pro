package whitelist

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTLSProvider serves body over HTTPS and returns a provider that trusts
// the test server and fetches both lists from it.
func newTLSProvider(t *testing.T, body string) *CloudflareProvider {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	provider := NewCloudflareProvider(server.URL, server.URL)
	provider.HTTPClient = server.Client()
	return provider
}

func TestFetchIPv4_ParsesLines(t *testing.T) {
	provider := newTLSProvider(t, "1.1.1.0/24\n2.2.2.0/24\n3.3.3.0/24\n")
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

func TestFetchIPv4_IgnoresCommentsAndEmptyLines(t *testing.T) {
	provider := newTLSProvider(t, "# Cloudflare IPv4 CIDRs\n1.1.1.0/24\n\n# Another comment\n2.2.2.0/24\n\n")
	cidrs, err := provider.FetchIPv4(context.Background())
	if err != nil {
		t.Fatalf("FetchIPv4: %v", err)
	}

	if len(cidrs) != 2 {
		t.Errorf("expected 2 CIDRs, got %d", len(cidrs))
	}
}

func TestFetchIPv4_HTTPError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	provider := NewCloudflareProvider(server.URL, "")
	provider.HTTPClient = server.Client()
	_, err := provider.FetchIPv4(context.Background())
	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
	if !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("expected error to contain 'HTTP 500', got: %v", err)
	}
}

func TestFetchIPv6_ParsesLines(t *testing.T) {
	provider := newTLSProvider(t, "2400:cb00::/32\n2606:4700::/32\n")
	cidrs, err := provider.FetchIPv6(context.Background())
	if err != nil {
		t.Fatalf("FetchIPv6: %v", err)
	}

	if len(cidrs) != 2 {
		t.Errorf("expected 2 CIDRs, got %d", len(cidrs))
	}
	if cidrs[0] != "2400:cb00::/32" {
		t.Errorf("expected first CIDR to be 2400:cb00::/32, got %s", cidrs[0])
	}
}

func TestCloudflareProvider_Timeout(t *testing.T) {
	// Server that sleeps longer than the timeout
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	provider := NewCloudflareProvider(server.URL, "")
	provider.HTTPClient = server.Client()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	if _, err := provider.FetchIPv4(ctx); err == nil {
		t.Error("expected timeout error, got nil")
	}
}

func TestCloudflareProviderRejectsInvalidFeed(t *testing.T) {
	for _, tc := range []struct {
		name string
		v6   bool
		body string
	}{
		{name: "invalid CIDR", body: "not-an-ip\n"},
		{name: "wrong family", body: "2400:cb00::/32\n"},
		{name: "empty", body: "# no ranges\n"},
		{name: "oversized", body: strings.Repeat("#", 64*1024+1)},
		{name: "whole IPv4 internet", body: "0.0.0.0/0\n"},
		{name: "IPv4 broader than /12", body: "104.0.0.0/11\n"},
		{name: "IPv6 broader than /29", v6: true, body: "2400::/16\n"},
		{name: "whole IPv6 internet", v6: true, body: "::/0\n"},
		{name: "valid entry with one broad entry", body: "1.1.1.0/24\n8.0.0.0/6\n"},
		{name: "private IPv4", body: "10.0.0.0/16\n"},
		{name: "private range inside a broader public prefix", body: "192.160.0.0/12\n"},
		{name: "loopback", body: "127.0.0.0/16\n"},
		{name: "link-local IPv4", body: "169.254.0.0/16\n"},
		{name: "carrier-grade NAT", body: "100.64.0.0/16\n"},
		{name: "multicast IPv4", body: "224.0.0.0/16\n"},
		{name: "documentation IPv4", body: "192.0.2.0/24\n"},
		{name: "unspecified IPv4", body: "0.0.0.0/16\n"},
		{name: "unique local IPv6", v6: true, body: "fd00::/32\n"},
		{name: "link-local IPv6", v6: true, body: "fe80::/32\n"},
		{name: "IPv6 loopback", v6: true, body: "::1/128\n"},
		{name: "IPv4-mapped IPv6", v6: true, body: "::ffff:1.2.3.0/120\n"},
		{name: "multicast IPv6", v6: true, body: "ff00::/32\n"},
		{name: "documentation IPv6", v6: true, body: "2001:db8::/32\n"},
		{name: "too many entries", body: manyCIDRs(maxCloudflareEntries + 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := newTLSProvider(t, tc.body)
			var err error
			if tc.v6 {
				_, err = provider.FetchIPv6(context.Background())
			} else {
				_, err = provider.FetchIPv4(context.Background())
			}
			if err == nil {
				t.Fatal("expected invalid feed to be rejected")
			}
		})
	}
}

func TestCloudflareProviderAcceptsCloudflareRanges(t *testing.T) {
	v4 := "173.245.48.0/20\n103.21.244.0/22\n103.22.200.0/22\n103.31.4.0/22\n141.101.64.0/18\n" +
		"108.162.192.0/18\n190.93.240.0/20\n188.114.96.0/20\n197.234.240.0/22\n198.41.128.0/17\n" +
		"162.158.0.0/15\n104.16.0.0/13\n104.24.0.0/14\n172.64.0.0/13\n131.0.72.0/22\n"
	v6 := "2400:cb00::/32\n2606:4700::/32\n2803:f800::/32\n2405:b500::/32\n2405:8100::/32\n2a06:98c0::/29\n2c0f:f248::/32\n"
	provider := newTLSProvider(t, v4)
	if got, err := provider.FetchIPv4(context.Background()); err != nil || len(got) != 15 {
		t.Fatalf("FetchIPv4 = %d entries, %v", len(got), err)
	}
	provider = newTLSProvider(t, v6)
	if got, err := provider.FetchIPv6(context.Background()); err != nil || len(got) != 7 {
		t.Fatalf("FetchIPv6 = %d entries, %v", len(got), err)
	}
}

func TestCloudflareProviderRefusesPlainHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("1.1.1.0/24\n"))
	}))
	defer server.Close()

	provider := NewCloudflareProvider(server.URL, server.URL)
	if _, err := provider.FetchIPv4(context.Background()); err == nil {
		t.Fatal("expected an http:// URL to be refused")
	}
	if _, err := provider.FetchIPv6(context.Background()); err == nil {
		t.Fatal("expected an http:// URL to be refused")
	}
}

// manyCIDRs returns n distinct public /24 ranges, one per line.
func manyCIDRs(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "%d.%d.%d.0/24\n", 11+i/65536, (i/256)%256, i%256)
	}
	return b.String()
}

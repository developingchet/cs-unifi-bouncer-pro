package feedhttp

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestIsInternalAddr(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1", true},
		{"10.1.2.3", true},
		{"172.16.0.1", true},
		{"192.168.0.1", true},
		{"169.254.169.254", true},
		{"100.64.0.1", true},
		{"100.127.255.254", true},
		{"0.0.0.0", true},
		{"224.0.0.251", true},
		{"::1", true},
		{"::", true},
		{"fe80::1", true},
		{"fe80::1%eth0", true},
		{"fd12::1", true},
		{"ff02::1", true},
		{"64:ff9b::a00:1", true},
		{"::ffff:127.0.0.1", true},
		{"::ffff:192.168.1.1", true},
		{"2002:7f00:1::1", true},
		{"8.8.8.8", false},
		{"100.128.0.1", false},
		{"::ffff:8.8.8.8", false},
		{"2606:4700::1111", false},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			addr, err := netip.ParseAddr(tt.addr)
			if err != nil {
				t.Fatal(err)
			}
			if got := IsInternalAddr(addr); got != tt.want {
				t.Fatalf("IsInternalAddr(%s) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

// A host name that resolves to a loopback address passes CheckRedirect, which
// only sees the name. The connection to it must still be refused when it is
// made on behalf of a redirect.
func TestClient_RedirectToHostResolvingToLoopbackIsRefused(t *testing.T) {
	var hit atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hit.Store(true)
	}))
	defer target.Close()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(target.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://localhost:"+port+"/", http.StatusFound)
	}))
	defer redirector.Close()

	client := NewClient(5 * time.Second)
	client.CheckRedirect = nil // leave only the dial-time guard in play
	resp, err := client.Get(redirector.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("redirect to a name resolving to loopback was followed")
	}
	if !strings.Contains(err.Error(), "internal address") {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit.Load() {
		t.Fatal("the redirect target received a request")
	}
}

// refuseInternalDial sees the address a name resolved to, so it decides for
// every redirect target whatever name led there.
func TestRefuseInternalDial(t *testing.T) {
	tests := []struct {
		address string
		refused bool
	}{
		{"127.0.0.1:80", true},
		{"10.0.0.5:443", true},
		{"169.254.169.254:80", true},
		{"[::1]:443", true},
		{"[::ffff:127.0.0.1]:80", true},
		{"[fe80::1%eth0]:443", true},
		{"0.0.0.0:80", true},
		{"8.8.8.8:443", false},
		{"[2606:4700::1111]:443", false},
		{"not-an-address:80", true},
		{"missing-port", true},
	}
	for _, tt := range tests {
		t.Run(tt.address, func(t *testing.T) {
			err := refuseInternalDial("tcp", tt.address, nil)
			if (err != nil) != tt.refused {
				t.Fatalf("refuseInternalDial(%s) = %v, want refused %v", tt.address, err, tt.refused)
			}
		})
	}
}

// The guarded dial refuses private, metadata and IPv6 loopback targets before
// any connection is attempted. CheckRedirect is removed so the dial check is
// the only one in play, as it is for a name that resolves to these addresses.
func TestClient_RedirectToInternalAddressIsRefusedAtDial(t *testing.T) {
	targets := []string{
		"http://10.0.0.5/",
		"http://169.254.169.254/latest/meta-data/",
		"http://[::1]/",
	}
	for _, target := range targets {
		t.Run(target, func(t *testing.T) {
			redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target, http.StatusFound)
			}))
			defer redirector.Close()

			client := NewClient(5 * time.Second)
			client.CheckRedirect = nil
			resp, err := client.Get(redirector.URL)
			if err == nil {
				resp.Body.Close()
				t.Fatalf("redirect to %s was followed", target)
			}
			if !strings.Contains(err.Error(), "internal address") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// A feed served from an internal host may redirect to another path on that
// host: the operator chose the host, so the redirect adds no new exposure.
func TestClient_RedirectWithinInternalHostIsFollowed(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/feed" {
			http.Redirect(w, r, server.URL+"/feed.txt", http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "198.51.100.1\n")
	}))
	defer server.Close()

	resp, err := NewClient(5 * time.Second).Get(server.URL + "/feed")
	if err != nil {
		t.Fatalf("same-host redirect: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "198.51.100.1\n" {
		t.Fatalf("body = %q", body)
	}
}

// A redirect from an internal feed host to a different host gets no such
// allowance, even through the default client with the name check in place.
func TestClient_RedirectFromInternalHostToAnotherInternalHostIsRefused(t *testing.T) {
	var hit atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hit.Store(true)
	}))
	defer target.Close()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(target.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://localhost:"+port+"/", http.StatusFound)
	}))
	defer redirector.Close()

	resp, err := NewClient(5 * time.Second).Get(redirector.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("redirect to a different internal host was followed")
	}
	if hit.Load() {
		t.Fatal("the redirect target received a request")
	}
}

func TestOriginalRequest(t *testing.T) {
	first, _ := http.NewRequest(http.MethodGet, "http://a.example/", nil)
	second, _ := http.NewRequest(http.MethodGet, "http://b.example/", nil)
	second.Response = &http.Response{Request: first}
	third, _ := http.NewRequest(http.MethodGet, "http://c.example/", nil)
	third.Response = &http.Response{Request: second}
	if got := originalRequest(third); got != first {
		t.Fatalf("originalRequest followed to %v, want the first request", got.URL)
	}
	if got := originalRequest(first); got != first {
		t.Fatal("a request without a Response is its own original")
	}
}

// The configured feed URL itself may be a private address; only requests
// created by a redirect are held to the dial check.
func TestClient_DirectRequestToPrivateAddressIsAllowed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "198.51.100.1\n")
	}))
	defer server.Close()

	resp, err := NewClient(5 * time.Second).Get(server.URL)
	if err != nil {
		t.Fatalf("direct request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "198.51.100.1\n" {
		t.Fatalf("body = %q", body)
	}
}

func TestCheckRedirect_RemovesReferer(t *testing.T) {
	from, _ := http.NewRequest(http.MethodGet, "https://feeds.example/list?token=secret", nil)
	to, _ := http.NewRequest(http.MethodGet, "https://cdn.example/list.txt", nil)
	to.Header.Set("Referer", from.URL.String())
	if err := CheckRedirect(to, []*http.Request{from}); err != nil {
		t.Fatal(err)
	}
	if got := to.Header.Get("Referer"); got != "" {
		t.Fatalf("Referer = %q after redirect, want it removed", got)
	}
}

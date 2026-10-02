package feedhttp

import (
	"net/http"
	"net/url"
	"testing"
)

func TestCheckFeedRedirect(t *testing.T) {
	req := func(raw string) *http.Request {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Request{URL: u}
	}
	tests := []struct {
		name    string
		from    string
		to      string
		hops    int
		wantErr bool
	}{
		{name: "https to public host", from: "https://feeds.example/list", to: "https://cdn.example/list.txt"},
		{name: "http to http", from: "http://feeds.example/list", to: "http://cdn.example/list.txt"},
		{name: "http upgraded to https", from: "http://feeds.example/list", to: "https://feeds.example/list"},
		{name: "https downgraded to http", from: "https://feeds.example/list", to: "http://feeds.example/list", wantErr: true},
		{name: "to cloud metadata", from: "https://feeds.example/list", to: "https://169.254.169.254/latest", wantErr: true},
		{name: "to private network", from: "https://feeds.example/list", to: "https://192.168.1.1/", wantErr: true},
		{name: "to loopback", from: "https://feeds.example/list", to: "https://127.0.0.1:9090/metrics", wantErr: true},
		{name: "to IPv6 loopback", from: "https://feeds.example/list", to: "https://[::1]/", wantErr: true},
		{name: "to localhost", from: "https://feeds.example/list", to: "https://localhost:8081/", wantErr: true},
		{name: "to upper-case localhost", from: "https://feeds.example/list", to: "https://LOCALHOST:8081/", wantErr: true},
		{name: "to localhost with trailing dot", from: "https://feeds.example/list", to: "https://localhost.:8081/", wantErr: true},
		{name: "to name under localhost", from: "https://feeds.example/list", to: "https://api.localhost/", wantErr: true},
		{name: "to carrier-grade NAT", from: "https://feeds.example/list", to: "https://100.64.0.1/", wantErr: true},
		{name: "to NAT64 prefix", from: "https://feeds.example/list", to: "https://[64:ff9b::7f00:1]/", wantErr: true},
		{name: "to IPv4-mapped loopback", from: "https://feeds.example/list", to: "https://[::ffff:127.0.0.1]/", wantErr: true},
		{name: "to IPv4-mapped private", from: "https://feeds.example/list", to: "https://[::ffff:10.0.0.1]/", wantErr: true},
		{name: "to multicast", from: "https://feeds.example/list", to: "https://224.0.0.1/", wantErr: true},
		{name: "to unspecified", from: "https://feeds.example/list", to: "https://0.0.0.0/", wantErr: true},
		{name: "to unique local IPv6", from: "https://feeds.example/list", to: "https://[fd00::1]/", wantErr: true},
		{name: "same internal name", from: "http://blocklists.lan/feed", to: "http://blocklists.lan/feed.txt"},
		{name: "same internal name in other case", from: "http://Blocklists.LAN/feed", to: "http://blocklists.lan./feed.txt"},
		{name: "same private address", from: "https://192.168.1.5/feed", to: "https://192.168.1.5/feed.txt"},
		{name: "same private address with explicit default port", from: "https://192.168.1.5/feed", to: "https://192.168.1.5:443/feed.txt"},
		{name: "same localhost", from: "http://localhost:8080/feed", to: "http://localhost:8080/feed.txt"},
		{name: "private address on another port", from: "https://192.168.1.5/feed", to: "https://192.168.1.5:8443/feed", wantErr: true},
		{name: "private address under another scheme", from: "http://192.168.1.5/feed", to: "https://192.168.1.5/feed", wantErr: true},
		{name: "internal host to another internal host", from: "https://192.168.1.5/feed", to: "https://192.168.1.6/feed", wantErr: true},
		{name: "internal name to localhost", from: "http://blocklists.lan/feed", to: "http://localhost/feed", wantErr: true},
		{name: "to public IPv6", from: "https://feeds.example/list", to: "https://[2606:4700::1111]/"},
		{name: "too many hops", from: "https://feeds.example/list", to: "https://cdn.example/list.txt", hops: maxFeedRedirects, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			via := []*http.Request{req(tt.from)}
			for len(via) < max(tt.hops, 1) {
				via = append(via, req(tt.from))
			}
			if err := CheckRedirect(req(tt.to), via); (err != nil) != tt.wantErr {
				t.Fatalf("CheckRedirect(%s -> %s) = %v, want error %v", tt.from, tt.to, err, tt.wantErr)
			}
		})
	}
}

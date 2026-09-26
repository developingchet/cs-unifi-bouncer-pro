package blocklist

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
		{name: "too many hops", from: "https://feeds.example/list", to: "https://cdn.example/list.txt", hops: maxFeedRedirects, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			via := []*http.Request{req(tt.from)}
			for len(via) < max(tt.hops, 1) {
				via = append(via, req(tt.from))
			}
			if err := checkFeedRedirect(req(tt.to), via); (err != nil) != tt.wantErr {
				t.Fatalf("checkFeedRedirect(%s -> %s) = %v, want error %v", tt.from, tt.to, err, tt.wantErr)
			}
		})
	}
}

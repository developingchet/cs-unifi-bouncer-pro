package controller

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseNetworkVersion(t *testing.T) {
	tests := []struct {
		in       string
		want     [3]int
		zoneOnly bool
		wantErr  bool
	}{
		{in: "10.6.106", want: [3]int{10, 6, 106}},
		{in: "10.5.67", want: [3]int{10, 5, 67}},
		{in: "11.0.83", want: [3]int{11, 0, 83}, zoneOnly: true},
		{in: "v12.1", want: [3]int{12, 1, 0}, zoneOnly: true},
		{in: "9.0.114-beta", want: [3]int{9, 0, 114}},
		{in: " 11 ", want: [3]int{11, 0, 0}, zoneOnly: true},
		{in: "", wantErr: true},
		{in: "atag_10.5.67", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			v, err := ParseNetworkVersion(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %+v", v)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := [3]int{v.Major, v.Minor, v.Patch}; got != tt.want {
				t.Errorf("parsed %v, want %v", got, tt.want)
			}
			if v.ZoneOnly() != tt.zoneOnly {
				t.Errorf("ZoneOnly() = %v, want %v", v.ZoneOnly(), tt.zoneOnly)
			}
		})
	}
}

func TestApplicationVersion(t *testing.T) {
	tests := []struct {
		name    string
		apiKey  string
		path    string
		body    string
		want    string
		wantErr bool
	}{
		{
			name:   "api key reads integration info",
			apiKey: "key",
			path:   "/proxy/network/integration/v1/info",
			body:   `{"applicationVersion":"10.5.67"}`,
			want:   "10.5.67",
		},
		{
			name: "session reads sysinfo",
			path: "/proxy/network/api/s/default/stat/sysinfo",
			body: `{"meta":{"rc":"ok"},"data":[{"build":"atag_10.6.106_1","version":"10.6.106"}]}`,
			want: "10.6.106",
		},
		{
			name:    "info without a version",
			apiKey:  "key",
			path:    "/proxy/network/integration/v1/info",
			body:    `{}`,
			wantErr: true,
		},
		{
			name:    "empty sysinfo",
			path:    "/proxy/network/api/s/default/stat/sysinfo",
			body:    `{"meta":{"rc":"ok"},"data":[]}`,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tt.path {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprint(w, tt.body)
			}))
			defer srv.Close()

			got, err := applicationVersion(context.Background(), newTestClient(srv.URL, tt.apiKey), "default")
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("version = %q, want %q", got, tt.want)
			}
		})
	}
}

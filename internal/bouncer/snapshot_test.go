package bouncer

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSameHostRequest(t *testing.T) {
	local := &net.TCPAddr{IP: net.ParseIP("172.18.0.5"), Port: 8081}
	tests := []struct {
		name   string
		remote string
		want   bool
	}{
		{"loopback v4", "127.0.0.1:50000", true},
		{"loopback v6", "[::1]:50000", true},
		{"own address", "172.18.0.5:50000", true},
		{"other container", "172.18.0.9:50000", false},
		{"docker gateway for a published port", "172.18.0.1:50000", false},
		{"unparsable", "garbage", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, DBSnapshotPath, nil)
			r.RemoteAddr = tt.remote
			r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, net.Addr(local)))
			if got := sameHostRequest(r); got != tt.want {
				t.Errorf("sameHostRequest(%s) = %v, want %v", tt.remote, got, tt.want)
			}
		})
	}
}

func TestDBSnapshotRefusesOtherHosts(t *testing.T) {
	b := &Bouncer{}
	r := httptest.NewRequest(http.MethodGet, DBSnapshotPath, nil)
	r.RemoteAddr = "192.0.2.50:40000"
	w := httptest.NewRecorder()
	b.dbSnapshot(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

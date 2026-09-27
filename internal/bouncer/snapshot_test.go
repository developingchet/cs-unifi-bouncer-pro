package bouncer

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
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

type fakeSnapshotStore struct{ body string }

func (f fakeSnapshotStore) WriteSnapshot(w io.Writer) (int64, error) {
	n, err := io.WriteString(w, f.body)
	return int64(n), err
}

func TestNewSnapshotServerWithoutSnapshotSupport(t *testing.T) {
	dir := t.TempDir()
	s, err := newSnapshotServer(struct{}{}, dir, zerolog.Nop())
	if err != nil || s != nil {
		t.Fatalf("newSnapshotServer = %v, %v; want nil, nil", s, err)
	}
	if _, err := os.Stat(filepath.Join(dir, SnapshotTokenFile)); !os.IsNotExist(err) {
		t.Errorf("token file written for a store without snapshots (stat err %v)", err)
	}
}

func TestSnapshotServer(t *testing.T) {
	dir := t.TempDir()
	s, err := newSnapshotServer(fakeSnapshotStore{body: "db"}, dir, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, SnapshotTokenFile))
	if err != nil {
		t.Fatal(err)
	}
	token := string(raw)
	if len(token) != 64 {
		t.Fatalf("token length = %d, want 64", len(token))
	}

	tests := []struct {
		name     string
		method   string
		remote   string
		token    string
		busy     bool
		wantCode int
		wantBody string
	}{
		{"loopback with token", http.MethodGet, "127.0.0.1:40000", token, false, http.StatusOK, "db"},
		{"loopback without token", http.MethodGet, "127.0.0.1:40000", "", false, http.StatusForbidden, ""},
		{"loopback with wrong token", http.MethodGet, "127.0.0.1:40000", token[:63] + "x", false, http.StatusForbidden, ""},
		{"other host with token", http.MethodGet, "192.0.2.50:40000", token, false, http.StatusForbidden, ""},
		{"post", http.MethodPost, "127.0.0.1:40000", token, false, http.StatusMethodNotAllowed, ""},
		{"snapshot already running", http.MethodGet, "127.0.0.1:40000", token, true, http.StatusTooManyRequests, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.busy {
				s.busy <- struct{}{}
				defer func() { <-s.busy }()
			}
			r := httptest.NewRequest(tt.method, DBSnapshotPath, nil)
			r.RemoteAddr = tt.remote
			if tt.token != "" {
				r.Header.Set(SnapshotTokenHeader, tt.token)
			}
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if w.Code != tt.wantCode {
				t.Errorf("status = %d, want %d", w.Code, tt.wantCode)
			}
			if tt.wantBody != "" && w.Body.String() != tt.wantBody {
				t.Errorf("body = %q, want %q", w.Body.String(), tt.wantBody)
			}
		})
	}
}

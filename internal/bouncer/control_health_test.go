package bouncer

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/banstate"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/firewall"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/rs/zerolog"
)

// TestHealth_ServesControlWithSnapshotToken runs the health server over a
// real database and checks that the control endpoints take the snapshot's
// token, answer 503 until the daemon enables them, and then ban.
func TestHealth_ServesControlWithSnapshotToken(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.NewBboltStore(dir, zerolog.Nop(), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	cfg := &config.Config{HealthAddr: "127.0.0.1:0", DataDir: dir}
	h, err := NewHealth(cfg, testutil.NewMockController(), store, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	ln, err := h.Listen()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- h.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		<-served
	})

	base := "http://" + ln.Addr().String()
	var token []byte
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if token, err = os.ReadFile(filepath.Join(dir, SnapshotTokenFile)); err == nil && len(token) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	post := func(tok string) int {
		req, err := http.NewRequest(http.MethodPost, base+ControlBanPath, strings.NewReader(`{"ip":"198.51.100.20"}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(SnapshotTokenHeader, tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}

	if got := post(string(token)); got != http.StatusServiceUnavailable {
		t.Fatalf("before EnableControl: status = %d, want 503", got)
	}
	fw := &mockFirewallManager{}
	h.EnableControl(&ManualActions{
		Claims: banstate.New(store, fw, []string{"default"}, false), Firewall: syncOnly{},
		History: store, Sites: []string{"default"}, BanTTL: time.Hour, Log: zerolog.Nop(),
	}, func() bool { return true })
	if got := post("wrong"); got != http.StatusForbidden {
		t.Fatalf("wrong token: status = %d, want 403", got)
	}
	if got := post(string(token)); got != http.StatusOK {
		t.Fatalf("with token: status = %d, want 200", got)
	}
	if entry, err := store.BanGet("198.51.100.20"); err != nil || entry == nil {
		t.Fatalf("ban not stored: %+v, %v", entry, err)
	}
}

// syncOnly is a firewall syncer whose syncs and reconciles do nothing.
type syncOnly struct{}

func (syncOnly) SyncDirty(context.Context, []string) error { return nil }
func (syncOnly) Reconcile(context.Context, []string) (*firewall.ReconcileResult, error) {
	return &firewall.ReconcileResult{}, nil
}

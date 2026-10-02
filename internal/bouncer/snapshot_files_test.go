package bouncer

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func writeAged(t *testing.T, dir, name string, age time.Duration) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	when := time.Now().Add(-age)
	if err := os.Chtimes(path, when, when); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRemoveStaleSnapshots(t *testing.T) {
	dir := t.TempDir()
	stale := writeAged(t, dir, "bouncer.db.status-123456789", time.Hour)
	fresh := writeAged(t, dir, "bouncer.db.status-987654321", time.Minute)
	database := writeAged(t, dir, "bouncer.db", 24*time.Hour)
	token := writeAged(t, dir, SnapshotTokenFile, 24*time.Hour)
	backup := writeAged(t, dir, "bouncer.db.status-backup", 24*time.Hour)
	suffixed := writeAged(t, dir, "bouncer.db.status-123.bak", 24*time.Hour)
	if err := os.Mkdir(filepath.Join(dir, "bouncer.db.status-555"), 0o700); err != nil {
		t.Fatal(err)
	}

	if got := RemoveStaleSnapshots(dir, zerolog.Nop()); got != 1 {
		t.Fatalf("removed %d files, want 1", got)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("stale snapshot still present (stat err %v)", err)
	}
	for _, kept := range []string{fresh, database, token, backup, suffixed, filepath.Join(dir, "bouncer.db.status-555")} {
		if _, err := os.Stat(kept); err != nil {
			t.Errorf("%s was removed: %v", filepath.Base(kept), err)
		}
	}
}

func TestRemoveStaleSnapshots_MissingDirectory(t *testing.T) {
	if got := RemoveStaleSnapshots(filepath.Join(t.TempDir(), "absent"), zerolog.Nop()); got != 0 {
		t.Fatalf("removed %d files from a directory that does not exist", got)
	}
}

func TestNewSnapshotServerRemovesStaleSnapshots(t *testing.T) {
	dir := t.TempDir()
	stale := writeAged(t, dir, "bouncer.db.status-42", time.Hour)
	if _, err := newSnapshotServer(fakeSnapshotStore{}, dir, zerolog.Nop()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale snapshot survived daemon start (stat err %v)", err)
	}
}

func TestDeadlineWriter(t *testing.T) {
	var sink []byte
	w := &deadlineWriter{w: writerFunc(func(p []byte) (int, error) { sink = append(sink, p...); return len(p), nil }),
		deadline: time.Now().Add(time.Hour)}
	if _, err := w.Write([]byte("ok")); err != nil || string(sink) != "ok" {
		t.Fatalf("write before the deadline: %v, %q", err, sink)
	}
	w.deadline = time.Now().Add(-time.Second)
	if _, err := w.Write([]byte("late")); !errors.Is(err, errSnapshotDeadline) {
		t.Fatalf("write after the deadline: err = %v, want errSnapshotDeadline", err)
	}
	if string(sink) != "ok" {
		t.Fatalf("data written after the deadline: %q", sink)
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// slowSnapshotStore writes in two parts with a pause between them.
type slowSnapshotStore struct{ pause time.Duration }

func (s slowSnapshotStore) WriteSnapshot(w io.Writer) (int64, error) {
	n, err := io.WriteString(w, "first")
	if err != nil {
		return int64(n), err
	}
	time.Sleep(s.pause)
	m, err := io.WriteString(w, "second")
	return int64(n + m), err
}

// A snapshot that outlasts its time limit is abandoned, which ends the read
// transaction the store holds while writing it.
func TestSnapshotServerStopsAfterTimeLimit(t *testing.T) {
	dir := t.TempDir()
	s, err := newSnapshotServer(slowSnapshotStore{pause: 80 * time.Millisecond}, dir, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	s.writeTimeout = 20 * time.Millisecond
	raw, err := os.ReadFile(filepath.Join(dir, SnapshotTokenFile))
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, DBSnapshotPath, nil)
	r.RemoteAddr = "127.0.0.1:40000"
	r.Header.Set(SnapshotTokenHeader, string(raw))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if body := w.Body.String(); body != "first" {
		t.Fatalf("body = %q, want the snapshot cut off after the first write", body)
	}
}

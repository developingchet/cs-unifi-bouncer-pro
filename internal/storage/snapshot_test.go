package storage

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestReadOnlyOpenOfLockedDatabase(t *testing.T) {
	dir := t.TempDir()
	rw, err := NewBboltStore(dir, zerolog.Nop(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer rw.Close()
	if err := rw.BanRecord("198.51.100.7", time.Now().Add(time.Hour), false); err != nil {
		t.Fatal(err)
	}

	if _, err := NewBboltStoreReadOnly(dir); !errors.Is(err, ErrDatabaseLocked) {
		t.Fatalf("read-only open while locked: err = %v, want ErrDatabaseLocked", err)
	}

	path := filepath.Join(t.TempDir(), "snapshot.db")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rw.(*bboltStore).WriteSnapshot(f); err != nil {
		t.Fatalf("WriteSnapshot: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	ro, err := OpenBboltFileReadOnly(path)
	if err != nil {
		t.Fatalf("open snapshot: %v", err)
	}
	defer ro.Close()
	if ok, err := ro.BanExists("198.51.100.7"); err != nil || !ok {
		t.Errorf("snapshot BanExists = %v, %v; want the recorded ban", ok, err)
	}
}

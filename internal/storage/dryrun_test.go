package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestDryRunStoreLeavesExistingDatabaseUnchanged(t *testing.T) {
	dir := t.TempDir()
	writable, err := NewBboltStore(dir, zerolog.Nop(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := writable.BanRecord("203.0.113.5", time.Now().Add(time.Hour), false); err != nil {
		t.Fatal(err)
	}
	if err := writable.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "bouncer.db")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewDryRunStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BanDelete("203.0.113.5"); err != nil {
		t.Fatal(err)
	}
	if err := store.BanRecord("203.0.113.6", time.Time{}, false); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("dry run changed the database")
	}
}

func TestDryRunStoreDoesNotCreateDatabase(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing")
	store, err := NewDryRunStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BanRecord("203.0.113.6", time.Time{}, false); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("dry run created data directory: %v", err)
	}
}

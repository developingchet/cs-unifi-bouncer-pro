package storage

import (
	"testing"

	"github.com/rs/zerolog"
)

func TestRecordMigrationPersists(t *testing.T) {
	dir := t.TempDir()
	s, err := NewBboltStore(dir, zerolog.Nop(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if done, err := s.MigrationApplied("example"); err != nil || done {
		t.Fatalf("new database reports migration applied: %v, %v", done, err)
	}
	if err := s.RecordMigration("example"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = NewBboltStore(dir, zerolog.Nop(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if done, err := s.MigrationApplied("example"); err != nil || !done {
		t.Fatalf("recorded migration after reopen = %v, %v", done, err)
	}
	if done, err := s.MigrationApplied("other"); err != nil || done {
		t.Fatalf("unrecorded migration = %v, %v", done, err)
	}
}

func TestDryRunStoreReadsButDoesNotRecordMigrations(t *testing.T) {
	dir := t.TempDir()
	s, err := NewBboltStore(dir, zerolog.Nop(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RecordMigration("example"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	dry, err := NewDryRunStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer dry.Close()
	if done, err := dry.MigrationApplied("example"); err != nil || !done {
		t.Fatalf("dry run did not read recorded migration: %v, %v", done, err)
	}
	if err := dry.RecordMigration("other"); err != nil {
		t.Fatal(err)
	}
	if done, err := dry.MigrationApplied("other"); err != nil || done {
		t.Fatalf("dry run recorded a migration: %v, %v", done, err)
	}
}

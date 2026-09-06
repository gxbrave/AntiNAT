package store_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

// RED 6a: opening a garbage (non-SQLite) file fails closed with an actionable
// error and leaves the file byte-identical.
func TestOpenFailsClosedOnGarbageFile(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "controller.db")
	garbage := []byte("this is definitely not a sqlite database file, not even close")
	if err := os.WriteFile(dbPath, garbage, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	before, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("ReadFile before: %v", err)
	}

	_, err = store.Open(dbPath)
	if err == nil {
		t.Fatal("Open succeeded on a garbage database file")
	}
	if !strings.Contains(err.Error(), "database") && !strings.Contains(err.Error(), "integrity") {
		t.Fatalf("error is not actionable: %v", err)
	}

	after, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("ReadFile after: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("Open modified or replaced the corrupt database file")
	}
}

// RED 6b: opening a truncated (half-deleted) valid database fails closed.
func TestOpenFailsClosedOnTruncatedDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "controller.db")
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	st, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	f, err := os.OpenFile(dbPath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if err := f.Truncate(st.Size() / 2); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	f.Close()

	if _, err := store.Open(dbPath); err == nil {
		t.Fatal("Open succeeded on a truncated database file")
	}
}

package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPartialApplyPreservesOldLKG(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if err := store.SeedLKG("forward-1", "target-old"); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginApply("op-1", "forward-1", "target-new"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = OpenStore(store.Dir())
	if err != nil {
		t.Fatal(err)
	}
	value, err := store.LKG("forward-1")
	if err != nil {
		t.Fatal(err)
	}
	if value != "target-old" {
		t.Fatalf("LKG after partial apply = %q, want target-old", value)
	}
}

func TestOpenStoreRestrictsExistingStateDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("state directory mode = %#o, want 0700", got)
	}
}

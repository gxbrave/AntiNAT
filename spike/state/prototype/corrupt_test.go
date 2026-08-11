package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCorruptBboltFailsClosed(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SeedLKG("forward-1", "target-old"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(filepath.Join(dir, "state.db"), 512); err != nil {
		t.Fatal(err)
	}
	if reopened, err := OpenStore(dir); err == nil {
		reopened.Close()
		t.Fatal("corrupt bbolt store opened successfully; want fail closed")
	}
}

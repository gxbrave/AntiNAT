package state

import "testing"

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

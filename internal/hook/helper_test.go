package hook_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/hook"
)

// newTestHookStore opens a fully-migrated controller store (which applies
// migrations/0010_hooks.sql) and then the hook store on the same database file,
// mirroring production composition. The clock is deterministic.
func newTestHookStore(t *testing.T) *hook.Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "controller.db")
	cst, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { cst.Close() })
	hs, err := hook.OpenStore(dbPath)
	if err != nil {
		t.Fatalf("hook open: %v", err)
	}
	t.Cleanup(func() { hs.Close() })
	hs.SetClock(func() time.Time { return time.Unix(1_700_000_000, 0) })
	return hs
}

func mustDefinition(t *testing.T, hs *hook.Store, name, url string) hook.Definition {
	t.Helper()
	d, err := hs.CreateDefinition(name, hook.KindWebhook, url)
	if err != nil {
		t.Fatalf("create definition: %v", err)
	}
	return d
}

func mustEnqueue(t *testing.T, hs *hook.Store, evt hook.Event) hook.Delivery {
	t.Helper()
	d, err := hs.EnqueueEvent(evt)
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	return d
}

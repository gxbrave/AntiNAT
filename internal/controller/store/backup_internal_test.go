package store

import (
	"path/filepath"
	"testing"
	"time"
)

// RED 5e: writers wait for a held write lock instead of failing instantly —
// the busy_timeout (>= 5000ms per the P03 spike) is actually in effect.
func TestBusyTimeoutWaitsForLockedWriter(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "controller.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	// The configured busy timeout must be >= 5000ms.
	var bt int
	if err := s.db.QueryRow("PRAGMA busy_timeout").Scan(&bt); err != nil {
		t.Fatalf("PRAGMA busy_timeout: %v", err)
	}
	if bt < 5000 {
		t.Fatalf("busy_timeout = %dms, want >= 5000ms", bt)
	}

	// Hold an exclusive write transaction on a second connection.
	blocker, err := openRawDB(dbPath)
	if err != nil {
		t.Fatalf("open blocker: %v", err)
	}
	defer blocker.Close()
	tx, err := blocker.Begin()
	if err != nil {
		t.Fatalf("blocker Begin: %v", err)
	}
	if _, err := tx.Exec(
		`INSERT OR REPLACE INTO global_settings (key, value, updated_at) VALUES ('lock-test', '1', 0)`,
	); err != nil {
		t.Fatalf("blocker write: %v", err)
	}

	// A store write must block (busy-wait), not fail.
	start := time.Now()
	done := make(chan error, 1)
	go func() {
		_, err := s.CreateForward(Forward{
			ID: "fwd-1", NodeID: "node-missing", Name: "web", Protocol: "tcp",
		})
		done <- err
	}()

	time.Sleep(300 * time.Millisecond)
	if err := tx.Commit(); err != nil { // release the write lock
		t.Fatalf("blocker Commit: %v", err)
	}

	err = <-done
	elapsed := time.Since(start)
	if err == nil {
		// It committed, meaning it waited for the lock. Fine (FK failure would
		// only fire after the lock is acquired).
		if elapsed < 200*time.Millisecond {
			t.Fatalf("write completed in %v, did not busy-wait", elapsed)
		}
	} else {
		// If it errored, it must be a write-time error that occurred AFTER the
		// lock was released (i.e. FK violation on the missing node), not an
		// immediate SQLITE_BUSY.
		if elapsed < 200*time.Millisecond {
			t.Fatalf("write failed in %v (%v): busy_timeout did not wait", elapsed, err)
		}
	}
}

// Package store implements the transactional SQLite-backed Controller
// persistence layer: migrations, nodes/forwards desired-and-delete
// transactions, the durable control outbox, idempotency keys, the durable
// admin event log, backup (VACUUM INTO + manifest) and low-disk policy.
//
// Frozen inputs (P04 contracts): docs/state-model.md §3/§4/§6 and the
// reviewed v0.8 execution plan §9.1. Driver: modernc.org/sqlite (non-CGO,
// validated by P03 spike sqlite-driver.json).
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// Sentinel errors used by the store API.
var (
	ErrEmptyPath       = errors.New("store: empty database path")
	ErrIntegrity       = errors.New("store: database failed integrity check")
	ErrNotMigrated     = errors.New("store: database did not reach schema version")
	ErrNotFound        = errors.New("store: record not found")
	ErrNodeNotFound    = errors.New("store: node not found")
	ErrForwardNotFound = errors.New("store: forward not found")
	ErrCASConflict     = errors.New("store: revision CAS conflict")
)

// Store is a configured SQLite-backed Controller store. A Store is safe for
// concurrent use by multiple goroutines; database/sql manages the pool and
// SQLite serializes writers via WAL + busy_timeout.
type Store struct {
	db           *sql.DB
	path         string
	minFreeBytes uint64
	diskFree     func(string) (uint64, error)
	clock        func() int64
}

// Open opens (or creates) the database at path, configures the frozen
// SQLite pragmas (WAL, busy_timeout >= 5000ms, foreign keys, full synchronous
// per the P03 spike), verifies integrity and applies every pending migration
// in order. On any failure it fails closed: the database file is left intact
// and the returned error is actionable.
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, ErrEmptyPath
	}
	// Ensure the parent directory exists so a fresh install can create the DB.
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := mkdirAll(dir); err != nil {
			return nil, fmt.Errorf("store: create data directory: %w", err)
		}
	}

	db, err := sql.Open("sqlite", dsnFor(path))
	if err != nil {
		return nil, fmt.Errorf("store: open %q: %w", path, err)
	}
	s := &Store{db: db, path: path, diskFree: DiskFreeBytes}

	if err := s.checkIntegrity(); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// dsnFor renders the frozen DSN: WAL, busy_timeout >= 5000ms, foreign keys
// enabled and full synchronous (P03 spike sqlite-driver.json).
func dsnFor(path string) string {
	return "file:" + path +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=foreign_keys(1)" +
		"&_pragma=synchronous(FULL)"
}

// Close closes the underlying database.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Path returns the database file path.
func (s *Store) Path() string { return s.path }

// SetClock replaces the store clock used by probe lifecycle writes and
// cleanup decisions. Production callers normally leave the default wall clock
// in place; injecting it keeps controller expiry/retention tests deterministic
// and lets a Manager and its store share one time source.
func (s *Store) SetClock(clock func() time.Time) {
	if clock == nil {
		s.clock = nil
		return
	}
	s.clock = func() int64 { return clock().Unix() }
}

func (s *Store) currentUnix() int64 {
	if s != nil && s.clock != nil {
		return s.clock()
	}
	return now()
}

// checkIntegrity fails closed on a missing or corrupt database.
func (s *Store) checkIntegrity() error {
	var result string
	if err := s.db.QueryRow("PRAGMA quick_check").Scan(&result); err != nil {
		return fmt.Errorf("%w: %v", ErrIntegrity, err)
	}
	if result != "ok" {
		return fmt.Errorf("%w: quick_check returned %q", ErrIntegrity, result)
	}
	return nil
}

// now returns Unix seconds; isolated for deterministic tests.
var now = func() int64 { return time.Now().Unix() }

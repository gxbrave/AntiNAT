package hook

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Definition is one webhook destination (api/openapi.yaml HookDefinition).
// AllowParams is the INTERNAL per-hook signing param allowlist (P1-2); it is
// never part of the frozen API response schema.
type Definition struct {
	ID          string
	Name        string
	Kind        string
	URL         string
	AllowParams []string
	Revision    uint64
	CreatedAt   int64
	UpdatedAt   int64
}

// Secret is hook-secret metadata (api/openapi.yaml HookSecret). The plaintext
// value is never part of this record; only the ciphertext lives in the store.
type Secret struct {
	ID        string
	SecretID  string
	Algorithm string
	Revision  uint64
	CreatedAt int64
	UpdatedAt int64
}

// SecretRow includes the at-rest material for the compact dispatch path.
type SecretRow struct {
	Secret
	Ciphertext []byte
	KeyID      string
}

// Delivery is one durable at-least-once delivery row.
type Delivery struct {
	ID                   string
	HookID               string
	EventID              string
	Kind                 string
	State                string
	AttemptCount         int
	MaxAttempts          int
	NextAttemptAt        int64
	PolicyJSON           string
	PayloadJSON          string
	ScriptB64            string
	SecretID             string
	LastError            string
	NodeID               string
	DecommissionDeadline int64
	CreatedAt            int64
	UpdatedAt            int64
}

// Store is the durable, SQLite-backed hook store. It owns the hook_* tables
// created by migrations/0010_hooks.sql and opens its own connection pool on the
// same WAL database file that the controller store opens (the controller store
// runs the migrations; the hook store never migrates). A Store is safe for
// concurrent use; SQLite serializes writers via WAL + busy_timeout.
type Store struct {
	db       *sql.DB
	path     string
	clock    func() int64
	jitterFn func(int64) int64
}

// OpenStore opens the hook store on database path. The database must already
// have been migrated to schema version 10 (the controller store applies
// migrations). Opening an unmigrated file fails closed.
func OpenStore(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("hook: empty database path")
	}
	db, err := sql.Open("sqlite", dsnFor(path))
	if err != nil {
		return nil, fmt.Errorf("hook: open %q: %w", path, err)
	}
	s := &Store{db: db, path: path, clock: hookNow}
	// Fail closed on any missing hook table instead of failing at first use.
	if err := s.checkSchema(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// dsnFor renders the same frozen DSN the controller store uses so both pools
// share one WAL-backed database file safely.
func dsnFor(path string) string {
	return "file:" + path +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=foreign_keys(1)" +
		"&_pragma=synchronous(FULL)"
}

var hookNow = func() int64 { return time.Now().Unix() }

// currentUnix returns the store clock (deterministic in tests).
func (s *Store) currentUnix() int64 {
	if s != nil && s.clock != nil {
		return s.clock()
	}
	return hookNow()
}

// SetClock injects a deterministic wall clock for tests.
func (s *Store) SetClock(clock func() time.Time) {
	if clock == nil {
		s.clock = hookNow
		return
	}
	s.clock = func() int64 { return clock().Unix() }
}

func (s *Store) checkSchema() error {
	for _, table := range []string{"hook_definitions", "hook_secrets", "hook_secret_bindings", "hook_deliveries"} {
		var n int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&n); err != nil {
			return fmt.Errorf("hook: inspect %s: %w", table, err)
		}
		if n != 1 {
			return fmt.Errorf("%w: missing hook table %s (migration 0010 not applied)", ErrNotMigrated, table)
		}
	}
	return nil
}

// Close closes the hook store's connection pool. The controller store owns the
// database lifecycle; callers close their own pools only.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Path returns the database file path.
func (s *Store) Path() string { return s.path }

// dbTX wraps a dedicated connection holding a raw BEGIN IMMEDIATE transaction.
// It satisfies the same Exec/QueryRow/Query subset as *sql.Tx so queue
// operations can run against either a committed-conn or a transaction.
type dbTX struct {
	conn *sql.Conn
}

func (t *dbTX) Exec(query string, args ...any) (sql.Result, error) {
	return t.conn.ExecContext(context.Background(), query, args...)
}

func (t *dbTX) QueryRow(query string, args ...any) *sql.Row {
	return t.conn.QueryRowContext(context.Background(), query, args...)
}

func (t *dbTX) Query(query string, args ...any) (*sql.Rows, error) {
	return t.conn.QueryContext(context.Background(), query, args...)
}

func (t *dbTX) Commit() error {
	_, err := t.conn.ExecContext(context.Background(), "COMMIT")
	return err
}

func (t *dbTX) Rollback() error {
	_, err := t.conn.ExecContext(context.Background(), "ROLLBACK")
	return err
}

func (t *dbTX) Close() error { return t.conn.Close() }

// beginImmediate starts the atomic writer transaction on a dedicated
// connection, matching the controller store's BEGIN IMMEDIATE discipline so
// concurrent readers never observe a partially-applied hook operation.
func (s *Store) beginImmediate() (*dbTX, error) {
	conn, err := s.db.Conn(context.Background())
	if err != nil {
		return nil, fmt.Errorf("hook: conn: %w", err)
	}
	if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		conn.Close()
		return nil, fmt.Errorf("hook: begin immediate: %w", err)
	}
	return &dbTX{conn: conn}, nil
}

var errHookNotMigrated = errors.New("hook: database schema version 10 is not applied")

// execer is the subset of *sql.Tx / *dbTX used by queue helpers.
type execer interface {
	Exec(query string, args ...any) (sql.Result, error)
	QueryRow(query string, args ...any) *sql.Row
	Query(query string, args ...any) (*sql.Rows, error)
}

// listQuery executes a rows query and scans via scanFn.
type scanFn func(*sql.Rows) error

func scanAll(rows *sql.Rows, err error, scan scanFn) error {
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := scan(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

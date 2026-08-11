package main

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

func openDatabase(path string) (*sql.DB, error) {
	dsn := "file:" + url.PathEscape(path) + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)&_pragma=foreign_keys(ON)&_pragma=synchronous(FULL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}
	return db, nil
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS events (
			id INTEGER PRIMARY KEY,
			writer INTEGER NOT NULL,
			sequence INTEGER NOT NULL,
			value TEXT NOT NULL,
			UNIQUE(writer, sequence)
		);
	`)
	return err
}

func backupDatabase(db *sql.DB, destination string) error {
	if _, err := db.Exec("VACUUM INTO ?", destination); err != nil {
		return fmt.Errorf("vacuum into backup: %w", err)
	}
	backup, err := os.Open(destination)
	if err != nil {
		return fmt.Errorf("open backup for sync: %w", err)
	}
	if err := backup.Sync(); err != nil {
		backup.Close()
		return fmt.Errorf("sync backup: %w", err)
	}
	if err := backup.Close(); err != nil {
		return fmt.Errorf("close backup: %w", err)
	}
	dir, err := os.Open(filepath.Dir(destination))
	if err != nil {
		return fmt.Errorf("open backup directory: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync backup directory: %w", err)
	}
	return nil
}

func databaseHealthy(path string) bool {
	db, err := openDatabase(path)
	if err != nil {
		return false
	}
	defer db.Close()
	var result string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&result); err != nil {
		return false
	}
	return result == "ok"
}

func writeUntilFull(db *sql.DB) error {
	if _, err := db.Exec("CREATE TABLE payloads (id INTEGER PRIMARY KEY, payload BLOB NOT NULL)"); err != nil {
		return err
	}
	var pageCount int
	if err := db.QueryRow("PRAGMA page_count").Scan(&pageCount); err != nil {
		return err
	}
	if _, err := db.Exec(fmt.Sprintf("PRAGMA max_page_count=%d", pageCount+2)); err != nil {
		return err
	}
	for range 1024 {
		if _, err := db.Exec("INSERT INTO payloads(payload) VALUES (randomblob(4096))"); err != nil {
			return err
		}
	}
	return nil
}

func isDatabaseFull(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "full")
}

func main() {}

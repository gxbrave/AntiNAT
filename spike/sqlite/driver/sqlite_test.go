package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
)

func TestMigrationsWALBusyTimeoutAndConcurrentWrites(t *testing.T) {
	db, err := openDatabase(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := migrate(db); err != nil {
		t.Fatal(err)
	}

	var journalMode string
	if err := db.QueryRow("PRAGMA journal_mode").Scan(&journalMode); err != nil {
		t.Fatal(err)
	}
	if journalMode != "wal" {
		t.Fatalf("journal_mode = %q, want wal", journalMode)
	}
	var busyTimeout int
	if err := db.QueryRow("PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
		t.Fatal(err)
	}
	if busyTimeout < 5000 {
		t.Fatalf("busy_timeout = %d, want at least 5000ms", busyTimeout)
	}

	const writers = 8
	const writesPerWriter = 32
	start := make(chan struct{})
	errs := make(chan error, writers)
	var wg sync.WaitGroup
	for writer := range writers {
		wg.Add(1)
		go func(writer int) {
			defer wg.Done()
			<-start
			for sequence := range writesPerWriter {
				_, err := db.Exec(
					"INSERT INTO events(writer, sequence, value) VALUES (?, ?, ?)",
					writer,
					sequence,
					strconv.Itoa(writer)+":"+strconv.Itoa(sequence),
				)
				if err != nil {
					errs <- err
					return
				}
			}
		}(writer)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent write: %v", err)
	}

	var count int
	if err := db.QueryRow("SELECT count(*) FROM events").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if want := writers * writesPerWriter; count != want {
		t.Fatalf("event count = %d, want %d", count, want)
	}
}

func TestVacuumIntoProducesConsistentBackup(t *testing.T) {
	dir := t.TempDir()
	db, err := openDatabase(filepath.Join(dir, "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := migrate(db); err != nil {
		t.Fatal(err)
	}

	for sequence := range 64 {
		if _, err := db.Exec(
			"INSERT INTO events(writer, sequence, value) VALUES (0, ?, ?)",
			sequence,
			fmt.Sprintf("before-backup:%d", sequence),
		); err != nil {
			t.Fatal(err)
		}
	}

	backupPath := filepath.Join(dir, "backup.db")
	if err := backupDatabase(db, backupPath); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		"INSERT INTO events(writer, sequence, value) VALUES (1, 0, 'after-backup')",
	); err != nil {
		t.Fatal(err)
	}

	backup, err := openDatabase(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	defer backup.Close()
	var count int
	if err := backup.QueryRow("SELECT count(*) FROM events").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 64 {
		t.Fatalf("backup event count = %d, want 64", count)
	}
	var quickCheck string
	if err := backup.QueryRow("PRAGMA quick_check").Scan(&quickCheck); err != nil {
		t.Fatal(err)
	}
	if quickCheck != "ok" {
		t.Fatalf("backup quick_check = %q, want ok", quickCheck)
	}
}

func TestCorruptDatabaseFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller.db")
	db, err := openDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := migrate(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO events(writer, sequence, value) VALUES (0, 0, 'durable')"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, 512); err != nil {
		t.Fatal(err)
	}

	if databaseHealthy(path) {
		t.Fatal("truncated database reported healthy; want fail closed")
	}
}

func TestMissingDatabaseFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.db")
	if databaseHealthy(path) {
		t.Fatal("missing database reported healthy; want fail closed without creating it")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("health check created missing database: %v", err)
	}
}

func TestFullDiskErrorIsReportedWithoutCorruptingDatabase(t *testing.T) {
	db, err := openDatabase(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := migrate(db); err != nil {
		t.Fatal(err)
	}

	if err := writeUntilFull(db); err == nil {
		t.Fatal("writeUntilFull returned nil, want SQLITE_FULL")
	} else if !isDatabaseFull(err) {
		t.Fatalf("writeUntilFull error = %v, want SQLITE_FULL", err)
	}
	var integrity string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&integrity); err != nil {
		t.Fatal(err)
	}
	if integrity != "ok" {
		t.Fatalf("integrity_check after SQLITE_FULL = %q, want ok", integrity)
	}
}

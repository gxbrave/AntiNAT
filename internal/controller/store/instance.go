package store

import (
	"database/sql"
	"errors"
	"fmt"
)

// InstanceID returns the Controller instance id stored in controller_instances,
// creating it on first use. It is stable across restarts and carried by every
// backup manifest (frozen state-model §6: split-brain and anti-rollback).
func (s *Store) InstanceID() (string, error) {
	var id string
	err := s.db.QueryRow("SELECT id FROM controller_instances LIMIT 1").Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("store: read instance id: %w", err)
	}

	id, err = randomHex(16)
	if err != nil {
		return "", fmt.Errorf("store: generate instance id: %w", err)
	}
	ts := now()
	if _, err := s.db.Exec(
		"INSERT INTO controller_instances (id, created_at, updated_at) VALUES (?, ?, ?)",
		id, ts, ts,
	); err != nil {
		// Concurrent first-use: return the row another writer created.
		var existing string
		if err2 := s.db.QueryRow("SELECT id FROM controller_instances LIMIT 1").Scan(&existing); err2 == nil {
			return existing, nil
		}
		return "", fmt.Errorf("store: write instance id: %w", err)
	}
	return id, nil
}

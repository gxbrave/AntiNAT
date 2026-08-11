package state

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	bucketLKG        = []byte("lkg")
	bucketPending    = []byte("pending")
	bucketOperations = []byte("operations")
	bucketOutbox     = []byte("outbox")
	bucketSecrets    = []byte("secrets")
	bucketSession    = []byte("session")
	bucketInbox      = []byte("inbox")
	bucketReceipts   = []byte("receipts")
	allBuckets       = [][]byte{bucketLKG, bucketPending, bucketOperations, bucketOutbox, bucketSecrets, bucketSession, bucketInbox, bucketReceipts}
)

type Store struct {
	dir string
	db  *bolt.DB
}

func OpenStore(dir string) (*Store, error) {
	if err := ensurePrivateDirectory(dir); err != nil {
		return nil, err
	}
	db, err := bolt.Open(filepath.Join(dir, "state.db"), 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, fmt.Errorf("open bbolt state: %w", err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, name := range allBuckets {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{dir: dir, db: db}, nil
}

func (s *Store) Dir() string { return s.dir }

func (s *Store) Close() error {
	if s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

func (s *Store) SeedLKG(forwardID, value string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketLKG).Put([]byte(forwardID), []byte(value))
	})
}

func (s *Store) BeginApply(operationID, forwardID, candidate string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		value := []byte(forwardID + "\x00" + candidate)
		return tx.Bucket(bucketPending).Put([]byte(operationID), value)
	})
}

func (s *Store) LKG(forwardID string) (string, error) {
	var value string
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketLKG).Get([]byte(forwardID))
		if raw == nil {
			return errors.New("LKG not found")
		}
		value = string(raw)
		return nil
	})
	return value, err
}

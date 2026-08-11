package state

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	bolt "go.etcd.io/bbolt"
)

const decommissionOperationID = "decommission-node"

type RecoveryState struct {
	Marker        string
	LKGPresent    bool
	SecretPresent bool
	AckPending    bool
}

func WriteSecretFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := ensurePrivateDirectory(dir); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(dir, ".antinat-secret-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return syncDirectory(dir)
}

func ensurePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("private directory %s has mode %v", path, info.Mode())
	}
	return nil
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func InitializeDecommissionFixture(dir string) error {
	store, err := OpenStore(dir)
	if err != nil {
		return err
	}
	defer store.Close()
	if err := store.SeedLKG("forward-1", "target-old"); err != nil {
		return err
	}
	if err := store.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSecrets).Put([]byte("hook-1"), []byte("encrypted-secret"))
	}); err != nil {
		return err
	}
	return WriteSecretFileAtomic(filepath.Join(dir, "identity.key"), []byte("test-identity"))
}

func Decommission(dir string, reached func(string)) error {
	store, err := OpenStore(dir)
	if err != nil {
		return err
	}
	defer store.Close()

	if err := store.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketOperations).Put([]byte(decommissionOperationID), []byte("INTENT_PERSISTED"))
	}); err != nil {
		return err
	}
	reached("intent")

	if err := WriteSecretFileAtomic(filepath.Join(dir, "terminal.marker"), []byte("DECOMMISSIONING")); err != nil {
		return err
	}
	reached("marker")

	if err := applyDecommissionSideEffects(store); err != nil {
		return err
	}
	reached("side_effect")

	if err := store.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketOperations).Put([]byte(decommissionOperationID), []byte("APPLIED"))
	}); err != nil {
		return err
	}
	if err := WriteSecretFileAtomic(filepath.Join(dir, "terminal.marker"), []byte("DECOMMISSIONED")); err != nil {
		return err
	}
	reached("result")

	if err := store.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketOutbox).Put([]byte(decommissionOperationID), []byte("SEMANTIC_ACK"))
	}); err != nil {
		return err
	}
	reached("ack")

	if err := store.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bucketOutbox).Delete([]byte(decommissionOperationID)); err != nil {
			return err
		}
		return tx.Bucket(bucketOperations).Delete([]byte(decommissionOperationID))
	}); err != nil {
		return err
	}
	reached("receipt")
	return nil
}

func applyDecommissionSideEffects(store *Store) error {
	if err := store.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bucketLKG).Delete([]byte("forward-1")); err != nil {
			return err
		}
		if err := tx.Bucket(bucketPending).Delete([]byte("op-1")); err != nil {
			return err
		}
		return tx.Bucket(bucketSecrets).Delete([]byte("hook-1"))
	}); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(store.dir, "identity.key")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDirectory(store.dir)
}

func RecoverDecommission(dir string) (RecoveryState, error) {
	markerBytes, err := os.ReadFile(filepath.Join(dir, "terminal.marker"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return RecoveryState{}, err
	}
	marker := string(markerBytes)
	store, err := OpenStore(dir)
	if err != nil {
		return RecoveryState{}, err
	}
	defer store.Close()

	if marker != "" {
		if marker != "DECOMMISSIONING" && marker != "DECOMMISSIONED" {
			return RecoveryState{}, fmt.Errorf("invalid terminal marker %q", marker)
		}
		var operationExists bool
		if err := store.db.View(func(tx *bolt.Tx) error {
			operationExists = tx.Bucket(bucketOperations).Get([]byte(decommissionOperationID)) != nil
			return nil
		}); err != nil {
			return RecoveryState{}, err
		}
		if err := applyDecommissionSideEffects(store); err != nil {
			return RecoveryState{}, err
		}
		if operationExists {
			if err := store.db.Update(func(tx *bolt.Tx) error {
				if err := tx.Bucket(bucketOperations).Put([]byte(decommissionOperationID), []byte("APPLIED")); err != nil {
					return err
				}
				return tx.Bucket(bucketOutbox).Put([]byte(decommissionOperationID), []byte("SEMANTIC_ACK"))
			}); err != nil {
				return RecoveryState{}, err
			}
		}
		if err := WriteSecretFileAtomic(filepath.Join(dir, "terminal.marker"), []byte("DECOMMISSIONED")); err != nil {
			return RecoveryState{}, err
		}
		marker = "DECOMMISSIONED"
	}

	state := RecoveryState{Marker: marker}
	if err := store.db.View(func(tx *bolt.Tx) error {
		state.LKGPresent = tx.Bucket(bucketLKG).Get([]byte("forward-1")) != nil
		state.AckPending = tx.Bucket(bucketOutbox).Get([]byte(decommissionOperationID)) != nil
		return nil
	}); err != nil {
		return RecoveryState{}, err
	}
	_, err = os.Stat(filepath.Join(dir, "identity.key"))
	state.SecretPresent = err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return RecoveryState{}, err
	}
	return state, nil
}

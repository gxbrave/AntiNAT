package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/security"
)

func TestLoadProviderPrivateKeyUsesConfiguredFile(t *testing.T) {
	dir := t.TempDir()
	keyring, err := security.LoadOrCreateKeyring(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	configured := filepath.Join(dir, "provider.key")
	raw, err := os.ReadFile(filepath.Join(dir, security.KeyringFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configured, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, security.KeyringFile)); err != nil {
		t.Fatal(err)
	}

	got, err := loadProviderPrivateKey(configured)
	if err != nil {
		t.Fatalf("load configured provider key: %v", err)
	}
	if len(got) != ed25519.PrivateKeySize {
		t.Fatalf("private key length = %d", len(got))
	}
	if string(got) != string(keyring.PrivateKey()) {
		t.Fatal("configured provider key does not match file")
	}
}

func TestLoadProviderPrivateKeyRejectsInsecureMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provider.key")
	if err := os.WriteFile(path, make([]byte, 4+8+ed25519.PrivateKeySize), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadProviderPrivateKey(path); err == nil {
		t.Fatal("insecure provider key mode accepted")
	}
}

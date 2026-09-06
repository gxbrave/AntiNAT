package api_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func testRouterControllerPublicKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate controller public key: %v", err)
	}
	return public
}

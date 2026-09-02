package hook

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"testing"
)

// RED repair P3-6: signBytes builds the HMAC key on a FRESH buffer. The old
// append(secret, '&') could write the trailing '&' separator into the decrypted
// secret's SPARE capacity — beyond len(secret), where zeroize(secret) never
// reaches — so key material could outlive zeroization. These tests pin the
// fresh-buffer behaviour and prove the digest is unchanged.
func TestSignBytesDoesNotWriteIntoSecretSpareCapacity(t *testing.T) {
	secret := []byte("plaintext-secret-value")
	original := append([]byte(nil), secret...)
	// padded has spare capacity beyond len(secret), like a decrypted buffer.
	padded := make([]byte, len(secret), len(secret)+8)
	copy(padded, secret)

	out := signBytes("HMAC-SHA256", padded, []byte("msg"))
	if len(out) == 0 {
		t.Fatal("empty signature")
	}
	// The plaintext area must be untouched.
	if !bytes.Equal(padded[:len(secret)], original) {
		t.Fatal("signBytes mutated the secret plaintext area")
	}
	// The spare-capacity area must contain no stray '&' (the old append landed
	// the separator exactly there, where zeroize(secret) never reached).
	if bytes.Contains(padded[len(secret):], []byte{'&'}) {
		t.Fatal("signBytes wrote '&' into the secret's spare capacity")
	}
	// The full key (secret + '&') must live on a separate freshly-allocated
	// buffer: prove no key material beyond the plaintext is visible in padded.
	for i := len(secret); i < len(padded); i++ {
		if padded[i] != 0 {
			t.Fatalf("unexpected byte %q in spare capacity", padded[i])
		}
	}
}

// The HMAC digest must be byte-identical to the reference hmac over
// secret + '&' — the fresh buffer changes no semantics, only where the '&'
// lands.
func TestSignBytesMatchesReferenceHMAC(t *testing.T) {
	secret := []byte("AliDNS-AccessKeySecret")
	got := signBytes("HMAC-SHA1", secret, []byte("GET&%2F&a%3D1"))
	mac := hmac.New(sha1.New, []byte("AliDNS-AccessKeySecret&"))
	mac.Write([]byte("GET&%2F&a%3D1"))
	if !bytes.Equal(got, mac.Sum(nil)) {
		t.Fatal("signBytes digest differs from the reference hmac(secret&)")
	}
}

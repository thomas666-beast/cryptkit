package cipher_test

import (
	"bytes"
	"testing"

	"github.com/thomas666-beast/cryptkit/cipher"
	"github.com/thomas666-beast/cryptkit/envelope"
)

func TestRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	msg := []byte("hello cryptkit — general-purpose crypto")

	for _, alg := range []envelope.Algorithm{
		envelope.AlgAES256GCM,
		envelope.AlgChaCha20Poly1305,
		envelope.AlgXChaCha20Poly1305,
	} {
		t.Run(alg.String(), func(t *testing.T) {
			ct, err := cipher.Encrypt(key, msg, cipher.Options{Algorithm: alg})
			if err != nil {
				t.Fatal(err)
			}
			pt, err := cipher.Decrypt(key, ct, cipher.Options{})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(pt, msg) {
				t.Fatalf("round-trip mismatch: %q != %q", pt, msg)
			}
		})
	}
}

func TestTamperedCiphertextFails(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	ct, err := cipher.Encrypt(key, []byte("secret"), cipher.DefaultOptions())
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if len(ct) == 0 {
		t.Fatal("encrypt returned empty ciphertext")
	}
	ct[len(ct)-1] ^= 0x01
	if _, err := cipher.Decrypt(key, ct, cipher.Options{RequireCommitment: true}); err == nil {
		t.Fatal("expected decrypt failure on tampered ciphertext")
	}
}

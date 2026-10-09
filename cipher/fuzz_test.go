package cipher_test

import (
	"bytes"
	"testing"

	"github.com/thomas666-beast/cryptkit/cipher"
	"github.com/thomas666-beast/cryptkit/context"
)

// FuzzDecryptNeverPanics ensures Decrypt returns an error (never panics) on
// arbitrary inputs, including adversarially crafted ones.
func FuzzDecryptNeverPanics(f *testing.F) {
	key := bytes.Repeat([]byte{0x42}, 32)

	// Seed with one valid envelope and one tampered one.
	ct, _ := cipher.Encrypt(key, []byte("seed"), cipher.DefaultOptions())
	f.Add(ct)
	tampered := append([]byte{}, ct...)
	if len(tampered) > 0 {
		tampered[len(tampered)-1] ^= 0x01
	}
	f.Add(tampered)
	f.Add([]byte{})
	f.Add([]byte("CRYPTKIT"))
	f.Add([]byte("CRYPTKIT\x01\x01\x00\x00\x00\x00\x00\x00"))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = cipher.Decrypt(key, data, cipher.Options{RequireCommitment: true})
		_, _ = cipher.Decrypt(key, data, cipher.Options{})
	})
}

// FuzzRoundTripWithContext checks that whatever we encrypt, we can decrypt.
func FuzzRoundTripWithContext(f *testing.F) {
	f.Add([]byte("hello"))
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte("A"), 1024))

	key := bytes.Repeat([]byte{0x11}, 32)
	ctx := context.Context{Purpose: "fuzz", Subject: "t:1"}
	opts := cipher.SecureOptions(ctx)

	f.Fuzz(func(t *testing.T, data []byte) {
		ct, err := cipher.Encrypt(key, data, opts)
		if err != nil {
			t.Skip()
		}
		pt, err := cipher.Decrypt(key, ct, opts)
		if err != nil {
			t.Fatalf("decrypt failed on own ciphertext: %v", err)
		}
		if !bytes.Equal(pt, data) {
			t.Fatal("round-trip mismatch")
		}
	})
}

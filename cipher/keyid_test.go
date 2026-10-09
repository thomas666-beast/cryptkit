package cipher_test

import (
	"bytes"
	"testing"

	"github.com/thomas666-beast/cryptkit/cipher"
	"github.com/thomas666-beast/cryptkit/keys"
)

func TestKeyIDSelection(t *testing.T) {
	k1, _ := keys.Generate(32, nil)
	k2, _ := keys.Generate(32, nil)

	// Encrypt with k2, tagged with its KeyID.
	ct, err := cipher.Encrypt(k2, []byte("hi"), cipher.Options{
		KeyID: keys.KeyIDBytes(k2),
	})
	if err != nil {
		t.Fatal(err)
	}

	ring := keys.NewKeyring()
	ring.Add("k1", k1, false)
	ring.Add("k2", k2, true)

	pt, which, err := cipher.DecryptWithKeyring(ring, ct, cipher.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, []byte("hi")) {
		t.Fatalf("bad plaintext: %q", pt)
	}
	if !bytes.Equal(which, k2) {
		t.Fatal("picked the wrong key")
	}
}

func TestKeyIDMismatchFails(t *testing.T) {
	k1, _ := keys.Generate(32, nil)
	// Fake KeyID that isn't in the ring.
	ct, _ := cipher.Encrypt(k1, []byte("x"), cipher.Options{
		KeyID: []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33},
	})
	ring := keys.NewKeyring()
	ring.Add("k1", k1, true)
	if _, _, err := cipher.DecryptWithKeyring(ring, ct, cipher.Options{}); err == nil {
		t.Fatal("expected no-matching-key error")
	}
}
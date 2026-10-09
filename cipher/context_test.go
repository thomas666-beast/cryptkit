package cipher_test

import (
	"bytes"
	"testing"

	"github.com/thomas666-beast/cryptkit/cipher"
	"github.com/thomas666-beast/cryptkit/context"
)

func TestContextBoundRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x99}, 32)
	ctx := context.Context{Purpose: "backup", Subject: "user:42"}
	msg := []byte("ctx-bound message")

	ct, err := cipher.Encrypt(key, msg, cipher.SecureOptions(ctx))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := cipher.Decrypt(key, ct, cipher.Options{
		Context:           ctx,
		RequireCommitment: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, msg) {
		t.Fatal("round-trip mismatch")
	}
}

func TestWrongContextFails(t *testing.T) {
	key := bytes.Repeat([]byte{0x99}, 32)
	ctxA := context.Context{Purpose: "backup", Subject: "user:42"}
	ctxB := context.Context{Purpose: "backup", Subject: "user:99"}

	ct, err := cipher.Encrypt(key, []byte("x"), cipher.SecureOptions(ctxA))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cipher.Decrypt(key, ct, cipher.Options{
		Context:           ctxB,
		RequireCommitment: true,
	}); err == nil {
		t.Fatal("expected context mismatch to fail")
	}
}

func TestWrongKeyFailsCommitment(t *testing.T) {
	keyA := bytes.Repeat([]byte{0xAA}, 32)
	keyB := bytes.Repeat([]byte{0xBB}, 32)
	ctx := context.Context{Purpose: "p", Subject: "s"}

	ct, err := cipher.Encrypt(keyA, []byte("secret"), cipher.SecureOptions(ctx))
	if err != nil {
		t.Fatal(err)
	}
	_, err = cipher.Decrypt(keyB, ct, cipher.Options{
		Context:           ctx,
		RequireCommitment: true,
	})
	if err == nil {
		t.Fatal("expected wrong-key commitment mismatch")
	}
	if err != cipher.ErrCommitCheck && err != cipher.ErrDecrypt {
		t.Fatalf("unexpected error: %v", err)
	}
}

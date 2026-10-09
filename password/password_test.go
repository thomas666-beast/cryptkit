package password_test

import (
	"testing"

	"github.com/thomas666-beast/cryptkit/password"
)

func TestHashAndVerify(t *testing.T) {
	h, err := password.HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if err := password.VerifyPassword("correct horse battery staple", h); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if err := password.VerifyPassword("wrong", h); err == nil {
		t.Fatal("expected mismatch")
	}
}

func TestNeedsRehash(t *testing.T) {
	weak := password.Argon2Params{
		Memory: 8 * 1024, Iterations: 1, Parallelism: 1,
		SaltLength: 16, KeyLength: 32,
	}
	h, err := password.HashPasswordWith("pw", weak)
	if err != nil {
		t.Fatal(err)
	}
	if !password.NeedsRehash(h) {
		t.Fatal("expected weak hash to need rehash")
	}
	h2, _ := password.HashPassword("pw")
	if password.NeedsRehash(h2) {
		t.Fatal("fresh hash should not need rehash")
	}
}

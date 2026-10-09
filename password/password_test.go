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

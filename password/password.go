package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrMismatch    = errors.New("cryptkit/password: password mismatch")
	ErrInvalidHash = errors.New("cryptkit/password: invalid hash format")
)

// Argon2Params controls Argon2id cost. Tune to your hardware.
type Argon2Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultArgon2Params is a reasonable baseline (~64 MiB, 3 passes).
func DefaultArgon2Params() Argon2Params {
	return Argon2Params{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 4,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// HashPassword returns a PHC-format Argon2id hash.
func HashPassword(pw string) (string, error) {
	return HashPasswordWith(pw, DefaultArgon2Params())
}

func HashPasswordWith(pw string, p Argon2Params) (string, error) {
	salt := make([]byte, p.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	return fmt.Sprintf(
		"$cryptkit$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Iterations, p.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// VerifyPassword checks pw against a PHC string; returns nil on success.
func VerifyPassword(pw, encoded string) error {
	switch {
	case strings.HasPrefix(encoded, "$cryptkit$argon2id$"):
		return verifyArgon2id(pw, encoded)
	case strings.HasPrefix(encoded, "$2a$"),
		strings.HasPrefix(encoded, "$2b$"),
		strings.HasPrefix(encoded, "$2y$"):
		if bcrypt.CompareHashAndPassword([]byte(encoded), []byte(pw)) != nil {
			return ErrMismatch
		}
		return nil
	}
	return ErrInvalidHash
}

func verifyArgon2id(pw, encoded string) error {
	// $cryptkit$argon2id$v=19$m=..,t=..,p=..$<salt>$<hash>
	// Split yields: ["", "cryptkit", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash]
	parts := strings.Split(encoded, "$")
	if len(parts) != 7 {
		return ErrInvalidHash
	}
	if parts[1] != "cryptkit" || parts[2] != "argon2id" {
		return ErrInvalidHash
	}

	var v int
	if _, err := fmt.Sscanf(parts[3], "v=%d", &v); err != nil || v != argon2.Version {
		return ErrInvalidHash
	}

	var m, t uint32
	var par uint8
	if _, err := fmt.Sscanf(parts[4], "m=%d,t=%d,p=%d", &m, &t, &par); err != nil {
		return ErrInvalidHash
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return ErrInvalidHash
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[6])
	if err != nil {
		return ErrInvalidHash
	}

	got := argon2.IDKey([]byte(pw), salt, t, m, par, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrMismatch
	}
	return nil
}

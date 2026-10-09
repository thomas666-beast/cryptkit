package keys

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
)

// DefaultKeySize is 32 bytes (256 bits) — matches all AEADs in cryptkit.
const DefaultKeySize = 32

// Generate returns n secure random bytes. n <= 0 => DefaultKeySize.
func Generate(n int, r io.Reader) ([]byte, error) {
	if n <= 0 {
		n = DefaultKeySize
	}
	if r == nil {
		r = rand.Reader
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}

// FromHex decodes a hex-encoded key.
func FromHex(s string) ([]byte, error) { return hex.DecodeString(strings.TrimSpace(s)) }

// FromBase64 decodes standard or raw base64.
func FromBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

// FromFile reads raw key bytes from a file.
func FromFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// FromEnv reads a hex- or base64-encoded key from an environment variable.
func FromEnv(name string) ([]byte, error) {
	v, ok := os.LookupEnv(name)
	if !ok {
		return nil, errors.New("cryptkit/keys: env var not set: " + name)
	}
	if b, err := FromHex(v); err == nil && len(b) > 0 {
		return b, nil
	}
	return FromBase64(v)
}

// ToHex / ToBase64 for storage.
func ToHex(b []byte) string    { return hex.EncodeToString(b) }
func ToBase64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

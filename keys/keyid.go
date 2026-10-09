package keys

import (
	"crypto/sha256"
	"encoding/hex"
)

// DefaultKeyIDLen is the truncated-hash length in bytes.
const DefaultKeyIDLen = 8

// KeyID returns SHA-256(key)[:DefaultKeyIDLen] as lowercase hex.
func KeyID(key []byte) string {
	h := sha256.Sum256(key)
	return hex.EncodeToString(h[:DefaultKeyIDLen])
}

// KeyIDBytes returns the raw (non-hex) key identifier bytes.
func KeyIDBytes(key []byte) []byte {
	h := sha256.Sum256(key)
	out := make([]byte, DefaultKeyIDLen)
	copy(out, h[:DefaultKeyIDLen])
	return out
}

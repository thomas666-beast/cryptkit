// Package context implements cryptkit's Context-Binding Layer (CBL).
//
// A Context is a structured, canonical, mandatory descriptor of "what this
// ciphertext is and who it belongs to". It is hashed and included as AEAD
// associated data, and re-verified at decrypt time.
//
// This defeats ciphertext substitution, cross-protocol replay, and
// domain-confusion attacks that plain AAD cannot express.
package context

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"sort"
	"strings"
)

var (
	ErrMissingPurpose = errors.New("cryptkit/context: purpose is required")
	ErrMissingSubject = errors.New("cryptkit/context: subject is required")
	ErrMismatch       = errors.New("cryptkit/context: context mismatch")
)

// Context is a structured descriptor bound to a ciphertext.
// Purpose and Subject are mandatory; the rest are optional.
type Context struct {
	Purpose string            // e.g. "backup", "session-token", "db-field:email"
	Subject string            // e.g. "user:42", "tenant:acme"
	Origin  string            // e.g. "host:db-01" (optional)
	Epoch   uint64            // e.g. unix seconds (optional, 0 = unset)
	Extra   map[string]string // arbitrary additional fields (optional)
}

// Canonical produces a deterministic byte encoding of the context.
// The encoding is stable regardless of map iteration order.
func (c Context) Canonical() ([]byte, error) {
	if c.Purpose == "" {
		return nil, ErrMissingPurpose
	}
	if c.Subject == "" {
		return nil, ErrMissingSubject
	}
	var b strings.Builder
	b.WriteString("cryptkit-ctx-v1\n")
	b.WriteString("purpose=")
	b.WriteString(c.Purpose)
	b.WriteByte('\n')
	b.WriteString("subject=")
	b.WriteString(c.Subject)
	b.WriteByte('\n')
	b.WriteString("origin=")
	b.WriteString(c.Origin)
	b.WriteByte('\n')
	var e [8]byte
	binary.BigEndian.PutUint64(e[:], c.Epoch)
	b.WriteString("epoch=")
	b.Write(e[:])
	b.WriteByte('\n')

	// Deterministic ordering for Extra.
	keys := make([]string, 0, len(c.Extra))
	for k := range c.Extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString("x-")
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(c.Extra[k])
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}

// Hash returns SHA-256(Canonical()).
func (c Context) Hash() ([32]byte, error) {
	can, err := c.Canonical()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(can), nil
}

// HashInto writes SHA-256(Canonical()) into h. Used to chain with other
// AAD material without allocating.
func (c Context) HashInto(h hash.Hash) error {
	can, err := c.Canonical()
	if err != nil {
		return err
	}
	_, err = h.Write(can)
	return err
}

// Equal reports whether two contexts are identical after canonicalization.
func (c Context) Equal(o Context) (bool, error) {
	a, err := c.Canonical()
	if err != nil {
		return false, err
	}
	b, err := o.Canonical()
	if err != nil {
		return false, err
	}
	if len(a) != len(b) {
		return false, nil
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0, nil
}

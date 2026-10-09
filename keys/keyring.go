// Package keys provides key material loading and, in keyring.go, a
// multi-key keyring supporting rotation.
package keys

import (
	"errors"
	"sync"
)

var (
	ErrKeyNotFound = errors.New("cryptkit/keys: key not found")
	ErrNoActiveKey = errors.New("cryptkit/keys: no active key")
)

// Keyring holds multiple named keys with exactly one active key.
// Encryption uses the active key. Decryption tries all keys in order.
type Keyring struct {
	mu     sync.RWMutex
	keys   map[string][]byte
	order  []string
	active string
}

func NewKeyring() *Keyring {
	return &Keyring{keys: map[string][]byte{}}
}

// Add registers a key under name. If active is true it becomes the active key.
func (k *Keyring) Add(name string, key []byte, active bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, exists := k.keys[name]; !exists {
		k.order = append(k.order, name)
	}
	k.keys[name] = key
	if active || k.active == "" {
		k.active = name
	}
}

// SetActive changes which key is used for encryption.
func (k *Keyring) SetActive(name string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, ok := k.keys[name]; !ok {
		return ErrKeyNotFound
	}
	k.active = name
	return nil
}

// ActiveKey returns the encryption key.
func (k *Keyring) ActiveKey() ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.active == "" {
		return nil, ErrNoActiveKey
	}
	return k.keys[k.active], nil
}

// Candidates returns all keys in insertion order. Callers can try each
// during decryption until one succeeds.
func (k *Keyring) Candidates() [][]byte {
	k.mu.RLock()
	defer k.mu.RUnlock()
	out := make([][]byte, 0, len(k.order))
	for _, n := range k.order {
		out = append(out, k.keys[n])
	}
	return out
}

// AddWithID registers a key under name and records its KeyID.
func (k *Keyring) AddWithID(name string, key []byte, active bool) {
	k.Add(name, key, active)
}

// FindByID returns the key whose KeyID matches id, or nil.
func (k *Keyring) FindByID(id string) ([]byte, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	for _, key := range k.keys {
		if KeyID(key) == id {
			return key, true
		}
	}
	return nil, false
}

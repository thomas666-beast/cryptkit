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
type Keyring struct {
	mu     sync.RWMutex
	keys   map[string][]byte
	order  []string
	active string
}

func NewKeyring() *Keyring {
	return &Keyring{keys: map[string][]byte{}}
}

// Add registers a key under name.
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

// Active returns the name of the active key.
func (k *Keyring) Active() string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.active
}

// Candidates returns all keys in insertion order.
func (k *Keyring) Candidates() [][]byte {
	k.mu.RLock()
	defer k.mu.RUnlock()
	out := make([][]byte, 0, len(k.order))
	for _, n := range k.order {
		out = append(out, k.keys[n])
	}
	return out
}

// Names returns key names in insertion order.
func (k *Keyring) Names() []string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	out := make([]string, len(k.order))
	copy(out, k.order)
	return out
}

// Remove deletes a key by name.
func (k *Keyring) Remove(name string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, ok := k.keys[name]; !ok {
		return
	}
	delete(k.keys, name)
	for i, n := range k.order {
		if n == name {
			k.order = append(k.order[:i], k.order[i+1:]...)
			break
		}
	}
	if k.active == name {
		k.active = ""
		if len(k.order) > 0 {
			k.active = k.order[0]
		}
	}
}

// FindByID returns the key whose KeyID matches id.
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

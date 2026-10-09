package cipher

import (
    "crypto/cipher"
    "errors"
    "sync"

    "github.com/thomas666-beast/cryptkit/envelope"
)

var (
    ErrUnknownAlgorithm = errors.New("cryptkit: unknown algorithm")
)

// AEADConstructor builds an AEAD from a 32-byte key.
type AEADConstructor func(key []byte) (cipher.AEAD, error)

// AEADInfo describes a registered AEAD.
type AEADInfo struct {
    ID        envelope.Algorithm
    Name      string
    NonceSize int
    KeySize   int
}

var (
    regMu sync.RWMutex
    reg   = map[envelope.Algorithm]struct {
        info AEADInfo
        ctor AEADConstructor
    }{}
)

// Register adds an AEAD implementation. Safe for concurrent use.
// Users may call this in init() to add custom algorithms.
func Register(info AEADInfo, ctor AEADConstructor) error {
    if info.ID == 0 {
        return errors.New("cryptkit: algorithm id 0 is reserved")
    }
    if ctor == nil {
        return errors.New("cryptkit: nil constructor")
    }
    regMu.Lock()
    defer regMu.Unlock()
    reg[info.ID] = struct {
        info AEADInfo
        ctor AEADConstructor
    }{info, ctor}
    return nil
}

// Lookup returns the AEADInfo for an algorithm, or ErrUnknownAlgorithm.
func Lookup(id envelope.Algorithm) (AEADInfo, bool) {
    regMu.RLock()
    defer regMu.RUnlock()
    e, ok := reg[id]
    if !ok {
        return AEADInfo{}, false
    }
    return e.info, true
}

func newAEAD(key []byte, id envelope.Algorithm) (cipher.AEAD, error) {
    regMu.RLock()
    e, ok := reg[id]
    regMu.RUnlock()
    if !ok {
        return nil, ErrUnknownAlgorithm
    }
    if len(key) != e.info.KeySize {
        return nil, ErrInvalidKey
    }
    return e.ctor(key)
}

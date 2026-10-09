package cipher

import (
    "crypto/rand"
    "errors"
    "io"

    "github.com/thomas666-beast/cryptkit/envelope"
)

var (
    ErrDecrypt     = errors.New("cryptkit: decryption failed")
    ErrInvalidKey  = errors.New("cryptkit: invalid key length")
    ErrUnsupported = errors.New("cryptkit: unsupported algorithm")
)

// Options controls encryption and decryption behaviour.
// Every field is optional; zero values fall back to safe defaults.
type Options struct {
    // Algorithm selects the AEAD. Zero => envelope.DefaultAlgorithm.
    Algorithm envelope.Algorithm

    // Nonce, if non-empty, is used verbatim. Length must match the
    // algorithm's nonce size. If nil, a random nonce is generated.
    Nonce []byte

    // AssociatedData is authenticated but not encrypted.
    AssociatedData []byte

    // Rand is the entropy source. Nil => crypto/rand.Reader.
    Rand io.Reader
}

func (o Options) rand() io.Reader {
    if o.Rand != nil {
        return o.Rand
    }
    return rand.Reader
}

func (o Options) alg() envelope.Algorithm {
    if o.Algorithm == 0 {
        return envelope.DefaultAlgorithm
    }
    return o.Algorithm
}

// Encrypt seals plaintext under key, returning a self-describing envelope.
func Encrypt(key, plaintext []byte, opts Options) ([]byte, error) {
    alg := opts.alg()
    info, ok := Lookup(alg)
    if !ok {
        return nil, ErrUnsupported
    }
    aead, err := newAEAD(key, alg)
    if err != nil {
        return nil, err
    }

    nonce := opts.Nonce
    if len(nonce) == 0 {
        nonce = make([]byte, info.NonceSize)
        if _, err := io.ReadFull(opts.rand(), nonce); err != nil {
            return nil, err
        }
    } else if len(nonce) != info.NonceSize {
        return nil, errors.New("cryptkit: nonce length mismatch")
    }

    hdr := &envelope.Header{
        Version:   envelope.Version,
        Algorithm: alg,
        KDF:       envelope.KDFNone,
        Nonce:     nonce,
    }
    hdrBytes := hdr.Marshal()
    aad := append(append([]byte{}, hdrBytes...), opts.AssociatedData...)

    ct := aead.Seal(nil, nonce, plaintext, aad)
    out := make([]byte, 0, len(hdrBytes)+len(ct))
    out = append(out, hdrBytes...)
    out = append(out, ct...)
    return out, nil
}

// Decrypt opens an envelope produced by Encrypt.
func Decrypt(key, blob []byte, opts Options) ([]byte, error) {
    hdr, off, err := envelope.ParseHeader(blob)
    if err != nil {
        return nil, err
    }
    if opts.Nonce != nil && !bytesEqual(opts.Nonce, hdr.Nonce) {
        return nil, errors.New("cryptkit: nonce override does not match header")
    }
    aead, err := newAEAD(key, hdr.Algorithm)
    if err != nil {
        return nil, err
    }
    aad := append(append([]byte{}, blob[:off]...), opts.AssociatedData...)
    pt, err := aead.Open(nil, hdr.Nonce, blob[off:], aad)
    if err != nil {
        return nil, ErrDecrypt
    }
    return pt, nil
}

func bytesEqual(a, b []byte) bool {
    if len(a) != len(b) {
        return false
    }
    for i := range a {
        if a[i] != b[i] {
            return false
        }
    }
    return true
}

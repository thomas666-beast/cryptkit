package cipher

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/thomas666-beast/cryptkit/audit"
	"github.com/thomas666-beast/cryptkit/context"
	"github.com/thomas666-beast/cryptkit/envelope"
)

var (
	ErrEncrypt      = errors.New("cryptkit: encryption failed")
	ErrDecrypt      = errors.New("cryptkit: decryption failed")
	ErrInvalidKey   = errors.New("cryptkit: invalid key length")
	ErrUnsupported  = errors.New("cryptkit: unsupported algorithm")
	ErrContextCheck = errors.New("cryptkit: context mismatch")
	ErrCommitCheck  = errors.New("cryptkit: key commitment mismatch")
)

// Options controls encryption and decryption behaviour.
type Options struct {
	Algorithm envelope.Algorithm
	Nonce     []byte
	AssociatedData []byte
	Context   context.Context
	RequireCommitment bool
	KeyID     []byte
	Audit     *audit.Log
	Rand      io.Reader
}

// DefaultOptions returns the library's recommended defaults.
func DefaultOptions() Options {
	return Options{RequireCommitment: true}
}

// SecureOptions returns the recommended high-assurance profile.
func SecureOptions(ctx context.Context) Options {
	return Options{Context: ctx, RequireCommitment: true}
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

func (o Options) hasContext() bool {
	return o.Context.Purpose != "" && o.Context.Subject != ""
}

func (o Options) buildAAD(hdrBytes []byte) ([]byte, error) {
	aad := append([]byte{}, hdrBytes...)
	aad = append(aad, o.AssociatedData...)
	if o.hasContext() {
		can, err := o.Context.Canonical()
		if err != nil {
			return nil, err
		}
		aad = append(aad, can...)
	}
	return aad, nil
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
			return nil, fmt.Errorf("%w: nonce: %v", ErrEncrypt, err)
		}
	} else if len(nonce) != info.NonceSize {
		return nil, fmt.Errorf("%w: nonce length mismatch", ErrEncrypt)
	}

	var flags uint8
	if opts.hasContext() {
		flags |= envelope.FlagHasContext
	}
	if opts.RequireCommitment {
		flags |= envelope.FlagHasCommitment
	}
	if len(opts.KeyID) > 0 {
		flags |= envelope.FlagHasKeyID
	}

	hdr := &envelope.Header{
		Version:   envelope.Version,
		Algorithm: alg,
		KDF:       envelope.KDFNone,
		Flags:     flags,
		Nonce:     nonce,
		KeyID:     opts.KeyID,
	}
	hdrBytes := hdr.Marshal()

	var commitment []byte
	if opts.RequireCommitment {
		commitment, err = computeCommitment(key, hdrBytes, opts.Context)
		if err != nil {
			return nil, fmt.Errorf("%w: commitment: %v", ErrEncrypt, err)
		}
	}

	aad, err := opts.buildAAD(hdrBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: aad: %v", ErrEncrypt, err)
	}

	ct := aead.Seal(nil, nonce, plaintext, aad)
	out := make([]byte, 0, len(hdrBytes)+len(commitment)+len(ct))
	out = append(out, hdrBytes...)
	out = append(out, commitment...)
	out = append(out, ct...)

	if opts.Audit != nil {
		ctxHash := ""
		if opts.hasContext() {
			h, _ := opts.Context.Hash()
			ctxHash = hex.EncodeToString(h[:])
		}
		_ = opts.Audit.Append(audit.Record{
			Op:          audit.OpEncrypt,
			Algorithm:   uint8(alg),
			ContextHash: ctxHash,
			Bytes:       int64(len(plaintext)),
		})
	}

	return out, nil
}

// Decrypt opens an envelope produced by Encrypt.
func Decrypt(key, blob []byte, opts Options) ([]byte, error) {
	v, err := envelope.ParseView(blob, commitLen)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	if opts.Nonce != nil && !bytesEqual(opts.Nonce, v.Header.Nonce) {
		return nil, fmt.Errorf("%w: nonce override does not match header", ErrDecrypt)
	}
	aead, err := newAEAD(key, v.Header.Algorithm)
	if err != nil {
		return nil, err
	}

	if v.Commitment != nil {
		if !verifyCommitment(key, v.HeaderRaw, v.Commitment, opts.Context) {
			return nil, ErrCommitCheck
		}
	} else if opts.RequireCommitment {
		return nil, ErrCommitCheck
	}

	if v.Header.HasContext() && !opts.hasContext() {
		return nil, ErrContextCheck
	}

	aad, err := opts.buildAAD(v.HeaderRaw)
	if err != nil {
		return nil, fmt.Errorf("%w: aad: %v", ErrDecrypt, err)
	}
	pt, err := aead.Open(nil, v.Header.Nonce, v.Ciphertext, aad)
	if err != nil {
		return nil, ErrDecrypt
	}

	if opts.Audit != nil {
		ctxHash := ""
		if opts.hasContext() {
			h, _ := opts.Context.Hash()
			ctxHash = hex.EncodeToString(h[:])
		}
		_ = opts.Audit.Append(audit.Record{
			Op:          audit.OpDecrypt,
			Algorithm:   uint8(v.Header.Algorithm),
			ContextHash: ctxHash,
			Bytes:       int64(len(pt)),
		})
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

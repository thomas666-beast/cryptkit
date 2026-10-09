package cipher

import (
	"crypto/rand"
	"errors"
	"io"

	"github.com/thomas666-beast/cryptkit/context"
	"github.com/thomas666-beast/cryptkit/envelope"
)

var (
	ErrDecrypt      = errors.New("cryptkit: decryption failed")
	ErrInvalidKey   = errors.New("cryptkit: invalid key length")
	ErrUnsupported  = errors.New("cryptkit: unsupported algorithm")
	ErrContextCheck = errors.New("cryptkit: context mismatch")
	ErrCommitCheck  = errors.New("cryptkit: key commitment mismatch")
)

// Options controls encryption and decryption behaviour.
type Options struct {
	Algorithm envelope.Algorithm

	// Nonce, if non-empty, used verbatim.
	Nonce []byte

	// AssociatedData is authenticated but not encrypted (raw).
	AssociatedData []byte

	// Context, if Purpose+Subject are set, is bound to the ciphertext
	// via the Context-Binding Layer. Decryption requires the same Context.
	Context context.Context

	// RequireCommitment adds a key-commitment tag (recommended).
	RequireCommitment bool

	// Rand is the entropy source. Nil => crypto/rand.Reader.
	Rand io.Reader
}

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
			return nil, err
		}
	} else if len(nonce) != info.NonceSize {
		return nil, errors.New("cryptkit: nonce length mismatch")
	}

	var flags uint8
	if opts.hasContext() {
		flags |= FlagHasContext
	}
	if opts.RequireCommitment {
		flags |= FlagHasCommitment
	}

	hdr := &envelope.Header{
		Version:   envelope.Version,
		Algorithm: alg,
		KDF:       envelope.KDFNone,
		Flags:     flags,
		Nonce:     nonce,
	}
	hdrBytes := hdr.Marshal()

	var commitment []byte
	if opts.RequireCommitment {
		commitment, err = computeCommitment(key, hdrBytes, opts.Context)
		if err != nil {
			return nil, err
		}
	}

	aad, err := opts.buildAAD(hdrBytes)
	if err != nil {
		return nil, err
	}

	ct := aead.Seal(nil, nonce, plaintext, aad)
	out := make([]byte, 0, len(hdrBytes)+len(commitment)+len(ct))
	out = append(out, hdrBytes...)
	out = append(out, commitment...)
	out = append(out, ct...)
	return out, nil
}

// Decrypt opens an envelope produced by Encrypt.
func Decrypt(key, blob []byte, opts Options) ([]byte, error) {
	v, err := envelope.ParseView(blob, commitLen)
	if err != nil {
		return nil, err
	}
	if opts.Nonce != nil && !bytesEqual(opts.Nonce, v.Header.Nonce) {
		return nil, errors.New("cryptkit: nonce override does not match header")
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
		return nil, err
	}
	pt, err := aead.Open(nil, v.Header.Nonce, v.Ciphertext, aad)
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

package kdf

import (
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/scrypt"
)

// Spec describes a KDF invocation. Users can implement their own
// by supplying a Derive function.
type Spec struct {
	Name   string
	Derive func(password, salt []byte, outLen int) ([]byte, error)
}

// Argon2idSpec builds an Argon2id KDF with caller-chosen cost.
func Argon2idSpec(memoryKiB, iterations uint32, parallelism uint8) Spec {
	return Spec{
		Name: "argon2id",
		Derive: func(pw, salt []byte, out int) ([]byte, error) {
			return argon2.IDKey(pw, salt, iterations, memoryKiB, parallelism, uint32(out)), nil
		},
	}
}

// ScryptSpec builds an scrypt KDF.
func ScryptSpec(N, r, p int) Spec {
	return Spec{
		Name: "scrypt",
		Derive: func(pw, salt []byte, out int) ([]byte, error) {
			return scrypt.Key(pw, salt, N, r, p, out)
		},
	}
}

// HKDFSpec builds an HKDF-SHA256 KDF.
func HKDFSpec(info []byte) Spec {
	return Spec{
		Name: "hkdf-sha256",
		Derive: func(pw, salt []byte, out int) ([]byte, error) {
			r := hkdf.New(sha256.New, pw, salt, info)
			b := make([]byte, out)
			if _, err := io.ReadFull(r, b); err != nil {
				return nil, err
			}
			return b, nil
		},
	}
}

// Derive runs the spec. salt may be nil; outLen must be > 0.
func Derive(spec Spec, password, salt []byte, outLen int) ([]byte, error) {
	if spec.Derive == nil {
		return nil, errors.New("cryptkit/kdf: spec has no Derive function")
	}
	if outLen <= 0 {
		return nil, errors.New("cryptkit/kdf: outLen must be > 0")
	}
	return spec.Derive(password, salt, outLen)
}

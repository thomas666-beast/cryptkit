package envelope

// Algorithm identifies the AEAD cipher used for a ciphertext.
type Algorithm uint8

const (
    AlgAES256GCM        Algorithm = 0x01
    AlgChaCha20Poly1305 Algorithm = 0x02
    AlgXChaCha20Poly1305 Algorithm = 0x03
)

// DefaultAlgorithm is XChaCha20-Poly1305: 24-byte nonce, safe for random
// nonces without counter management.
const DefaultAlgorithm = AlgXChaCha20Poly1305

// NonceSize returns the required nonce length for the algorithm.
func (a Algorithm) NonceSize() int {
    switch a {
    case AlgAES256GCM, AlgChaCha20Poly1305:
        return 12
    case AlgXChaCha20Poly1305:
        return 24
    }
    return 0
}

func (a Algorithm) String() string {
    switch a {
    case AlgAES256GCM:
        return "AES-256-GCM"
    case AlgChaCha20Poly1305:
        return "ChaCha20-Poly1305"
    case AlgXChaCha20Poly1305:
        return "XChaCha20-Poly1305"
    }
    return "unknown"
}

// KDF identifies the key-derivation function used, if any.
type KDF uint8

const (
    KDFNone     KDF = 0x00
    KDFArgon2id KDF = 0x01
    KDFScrypt   KDF = 0x02
    KDFHKDF     KDF = 0x03
)

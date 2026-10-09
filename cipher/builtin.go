package cipher

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/thomas666-beast/cryptkit/envelope"
	"golang.org/x/crypto/chacha20poly1305"
)

func init() {
	_ = Register(
		AEADInfo{ID: envelope.AlgAES256GCM, Name: "AES-256-GCM", NonceSize: 12, KeySize: 32},
		func(key []byte) (cipher.AEAD, error) {
			b, err := aes.NewCipher(key)
			if err != nil {
				return nil, err
			}
			return cipher.NewGCM(b)
		},
	)
	_ = Register(
		AEADInfo{ID: envelope.AlgChaCha20Poly1305, Name: "ChaCha20-Poly1305", NonceSize: 12, KeySize: 32},
		func(key []byte) (cipher.AEAD, error) { return chacha20poly1305.New(key) },
	)
	_ = Register(
		AEADInfo{ID: envelope.AlgXChaCha20Poly1305, Name: "XChaCha20-Poly1305", NonceSize: 24, KeySize: 32},
		func(key []byte) (cipher.AEAD, error) { return chacha20poly1305.NewX(key) },
	)
}

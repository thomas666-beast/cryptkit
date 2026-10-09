package cipher_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/thomas666-beast/cryptkit/internal/testvec/wycheproof"
)

func runWycheproofAEAD(t *testing.T, path, kind string) {
	tf, err := wycheproof.Load(path)
	if err != nil {
		t.Skipf("vectors not available: %v", err)
	}
	for _, g := range tf.TestGroups {
		for _, tc := range g.Tests {
			if tc.Result != "valid" && tc.Result != "invalid" {
				continue
			}
			key, err := hex.DecodeString(tc.Key)
			if err != nil {
				continue
			}
			iv, _ := hex.DecodeString(tc.IV)
			aad, _ := hex.DecodeString(tc.AAD)
			msg, _ := hex.DecodeString(tc.Msg)
			ct, _ := hex.DecodeString(tc.Ct)
			tag, _ := hex.DecodeString(tc.Tag)

			aead, err := newAEADFor(kind, key)
			if err != nil {
				t.Fatalf("TC%d: aead: %v", tc.TCID, err)
			}
			if len(iv) != aead.NonceSize() {
				continue
			}
			if len(tag) != aead.Overhead() {
				continue
			}

			if tc.Result == "valid" {
				got := aead.Seal(nil, iv, msg, aad)
				want := append(append([]byte{}, ct...), tag...)
				if !bytes.Equal(got, want) {
					t.Fatalf("TC%d (%s): seal mismatch", tc.TCID, tc.Comment)
				}
			}

			if tc.Result == "invalid" {
				blob := append(append([]byte{}, ct...), tag...)
				if _, err := aead.Open(nil, iv, blob, aad); err == nil {
					t.Fatalf("TC%d (%s): invalid vector accepted", tc.TCID, tc.Comment)
				}
			}
		}
	}
}

func newAEADFor(kind string, key []byte) (cipher.AEAD, error) {
	switch kind {
	case "aes-gcm":
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case "chacha20-poly1305":
		return chacha20poly1305.New(key)
	}
	return nil, nil
}

func TestWycheproofAESGCM(t *testing.T) {
	path := filepath.Join("..", "internal", "testvec", "wycheproof", "aes_gcm_test.json")
	runWycheproofAEAD(t, path, "aes-gcm")
}

func TestWycheproofChaCha20Poly1305(t *testing.T) {
	path := filepath.Join("..", "internal", "testvec", "wycheproof", "chacha20_poly1305_test.json")
	runWycheproofAEAD(t, path, "chacha20-poly1305")
}

package cipher

import (
	"errors"

	"github.com/thomas666-beast/cryptkit/envelope"
	"github.com/thomas666-beast/cryptkit/keys"
)

var ErrNoMatchingKey = errors.New("cryptkit: no key in ring matches envelope")

// DecryptWithKeyring decrypts using a keyring. If the envelope carries a
// key ID, the matching key is selected directly; otherwise all keys are
// tried in insertion order.
func DecryptWithKeyring(ring *keys.Keyring, blob []byte, opts Options) ([]byte, []byte, error) {
	hdr, _, err := envelope.ParseHeader(blob)
	if err != nil {
		return nil, nil, err
	}
	if hdr.HasKeyID() {
		key, ok := ring.FindByID(hexString(hdr.KeyID))
		if !ok {
			return nil, nil, ErrNoMatchingKey
		}
		pt, err := Decrypt(key, blob, opts)
		if err != nil {
			return nil, nil, err
		}
		return pt, key, nil
	}
	// Fallback: trial decryption.
	var lastErr error
	for _, k := range ring.Candidates() {
		pt, err := Decrypt(k, blob, opts)
		if err == nil {
			return pt, k, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = ErrNoMatchingKey
	}
	return nil, nil, lastErr
}

// hexString avoids importing encoding/hex at package top level.
func hexString(b []byte) string {
	const d = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, x := range b {
		out[i*2] = d[x>>4]
		out[i*2+1] = d[x&0x0f]
	}
	return string(out)
}

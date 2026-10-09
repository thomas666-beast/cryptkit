package cipher

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// NonceDeriver produces the per-chunk nonce for chunk index i.
type NonceDeriver func(baseNonce []byte, index uint64, nonceSize int) []byte

// DefaultNonceDeriver: nonce_i = HMAC-SHA256(baseNonce, uint64_be(i))[:nonceSize]
func DefaultNonceDeriver(base []byte, i uint64, ns int) []byte {
	mac := hmac.New(sha256.New, base)
	var idx [8]byte
	binary.BigEndian.PutUint64(idx[:], i)
	mac.Write(idx[:])
	sum := mac.Sum(nil)
	return sum[:ns]
}

// chunkIndexAAD returns AAD bytes binding a chunk to its index and finality.
func chunkIndexAAD(headerAAD []byte, index uint64, final bool) []byte {
	out := make([]byte, 0, len(headerAAD)+9)
	out = append(out, headerAAD...)
	var i [8]byte
	binary.BigEndian.PutUint64(i[:], index)
	out = append(out, i[:]...)
	if final {
		out = append(out, 0x01)
	} else {
		out = append(out, 0x00)
	}
	return out
}

var ErrTruncatedChunk = errors.New("cryptkit: truncated chunk")

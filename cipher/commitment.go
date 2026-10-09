package cipher

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/thomas666-beast/cryptkit/context"
)

const commitLen = 32

func commitKey(primaryKey []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, primaryKey, nil, []byte("cryptkit/commitment/v1"))
	out := make([]byte, 32)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

// computeCommitment = HMAC-SHA256(commitKey, headerBytes || (ctxHash if ctx present))
func computeCommitment(primaryKey, headerBytes []byte, ctx context.Context) ([]byte, error) {
	ck, err := commitKey(primaryKey)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, ck)
	mac.Write(headerBytes)
	if ctx.Purpose != "" && ctx.Subject != "" {
		ch, err := ctx.Hash()
		if err != nil {
			return nil, err
		}
		mac.Write(ch[:])
	}
	return mac.Sum(nil), nil
}

// verifyCommitment is constant-time.
func verifyCommitment(primaryKey, headerBytes, want []byte, ctx context.Context) bool {
	got, err := computeCommitment(primaryKey, headerBytes, ctx)
	if err != nil || len(got) != len(want) {
		return false
	}
	var diff byte
	for i := range got {
		diff |= got[i] ^ want[i]
	}
	return diff == 0
}

// appendCommitment writes the commitment tag just after headerBytes.
func appendCommitment(dst, primaryKey, headerBytes []byte, ctx context.Context) ([]byte, error) {
	c, err := computeCommitment(primaryKey, headerBytes, ctx)
	if err != nil {
		return nil, err
	}
	return append(dst, c...), nil
}

// flag bits in envelope header
const (
	FlagHasContext    uint8 = 0x01
	FlagHasCommitment uint8 = 0x02
)

// encodeUint32 helper
func putUint32(b []byte, v uint32) {
	binary.BigEndian.PutUint32(b, v)
}

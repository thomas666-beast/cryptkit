package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash"
	"time"
)

var (
	ErrRecordUnsigned = errors.New("cryptkit/audit: record has no signature")
	ErrBadSignature   = errors.New("cryptkit/audit: signature mismatch")
	ErrChainBroken    = errors.New("cryptkit/audit: chain broken")
)

// Op identifies what was done. Logged verbatim.
type Op string

const (
	OpEncrypt        Op = "encrypt"
	OpDecrypt        Op = "decrypt"
	OpEncryptStream  Op = "encrypt-stream"
	OpDecryptStream  Op = "decrypt-stream"
	OpRewrap         Op = "rewrap"
	OpHashPassword   Op = "hash-password"
	OpVerifyPassword Op = "verify-password"
)

// Record is one entry in the tamper-evident log.
type Record struct {
	Seq         uint64    `json:"seq"`
	Timestamp   time.Time `json:"ts"`
	Op          Op        `json:"op"`
	Algorithm   uint8     `json:"alg,omitempty"`
	ContextHash string    `json:"ctx,omitempty"` // hex SHA-256 of canonical context
	KeyID       string    `json:"kid,omitempty"` // opaque key identifier
	Bytes       int64     `json:"bytes,omitempty"`
	PrevHash    string    `json:"prev"`     // hex, "" for first record
	Signature   string    `json:"sig"`      // hex HMAC-SHA256
}

// canonicalRecordBytes returns the byte encoding that is signed.
// Signature field itself is excluded.
func (r Record) canonicalRecordBytes() ([]byte, error) {
	tmp := r
	tmp.Signature = ""
	return json.Marshal(tmp)
}

// sign fills r.Signature using key.
func (r *Record) sign(key []byte) error {
	body, err := r.canonicalRecordBytes()
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	r.Signature = hexEncode(mac.Sum(nil))
	return nil
}

// verify checks r.Signature.
func (r Record) verify(key []byte) error {
	if r.Signature == "" {
		return ErrRecordUnsigned
	}
	want := r.Signature
	cp := r
	cp.Signature = ""
	body, err := cp.canonicalRecordBytes()
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	got := hexEncode(mac.Sum(nil))
	if !hmac.Equal([]byte(got), []byte(want)) {
		return ErrBadSignature
	}
	return nil
}

// hashRecord returns SHA-256 of the record including its signature.
// This is what the next record references via PrevHash.
func (r Record) hashRecord() string {
	body, _ := json.Marshal(r)
	h := sha256.Sum256(body)
	return hexEncode(h[:])
}

// hashBytesOf is used to build deterministic input to sign() in case the
// caller wants streaming (currently just a helper, kept for symmetry).
func hashBytesOf(data []byte) string {
	h := sha256.Sum256(data)
	return hexEncode(h[:])
}

// helpers to avoid importing encoding/hex everywhere.
func hexEncode(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, x := range b {
		out[i*2] = hexdigits[x>>4]
		out[i*2+1] = hexdigits[x&0x0f]
	}
	return string(out)
}

var _ hash.Hash // keep import in case future versions add streaming

var _ = binary.BigEndian

package envelope

import (
	"encoding/binary"
	"errors"
)

const (
	Magic       = "CRYPTKIT"
	Version     = 0x01
	MagicLen    = 8
	FixedHdrLen = 16

	FlagHasContext    uint8 = 0x01
	FlagHasCommitment uint8 = 0x02
	FlagHasKeyID      uint8 = 0x04
)

var (
	ErrInvalidMagic   = errors.New("cryptkit: invalid magic")
	ErrUnsupportedVer = errors.New("cryptkit: unsupported format version")
	ErrTruncated      = errors.New("cryptkit: truncated header")
)

// Header is the parsed, unencrypted prefix of an envelope.
type Header struct {
	Version   uint8
	Algorithm Algorithm
	KDF       KDF
	Flags     uint8
	KDFParams []byte
	Nonce     []byte
	KeyID     []byte // nil if absent
}

// Marshal writes header bytes. Layout:
//
//	[ magic 8 ][ ver 1 ][ alg 1 ][ kdf 1 ][ flags 1 ][ kdfLen 4 ]
//	[ kdfParams N ][ nonce M ][ (if flag bit 2) keyIDLen 2 || keyID K ]
func (h *Header) Marshal() []byte {
	out := make([]byte, 0, FixedHdrLen+len(h.KDFParams)+len(h.Nonce)+2+len(h.KeyID))
	out = append(out, Magic...)
	out = append(out, h.Version, byte(h.Algorithm), byte(h.KDF), h.Flags)
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(h.KDFParams)))
	out = append(out, l[:]...)
	out = append(out, h.KDFParams...)
	out = append(out, h.Nonce...)
	if h.Flags&FlagHasKeyID != 0 {
		var kl [2]byte
		binary.BigEndian.PutUint16(kl[:], uint16(len(h.KeyID)))
		out = append(out, kl[:]...)
		out = append(out, h.KeyID...)
	}
	return out
}

// ParseHeader reads a header, returning the offset where ciphertext begins.
func ParseHeader(buf []byte) (*Header, int, error) {
	if len(buf) < FixedHdrLen {
		return nil, 0, ErrTruncated
	}
	if string(buf[:MagicLen]) != Magic {
		return nil, 0, ErrInvalidMagic
	}
	if buf[MagicLen] != Version {
		return nil, 0, ErrUnsupportedVer
	}
	h := &Header{
		Version:   buf[MagicLen],
		Algorithm: Algorithm(buf[MagicLen+1]),
		KDF:       KDF(buf[MagicLen+2]),
		Flags:     buf[MagicLen+3],
	}
	n := binary.BigEndian.Uint32(buf[MagicLen+4 : MagicLen+8])
	off := FixedHdrLen
	if uint32(len(buf)-off) < n {
		return nil, 0, ErrTruncated
	}
	h.KDFParams = buf[off : off+int(n)]
	off += int(n)
	ns := h.Algorithm.NonceSize()
	if ns == 0 {
		return nil, 0, errors.New("cryptkit: unknown algorithm")
	}
	if len(buf)-off < ns {
		return nil, 0, ErrTruncated
	}
	h.Nonce = buf[off : off+ns]
	off += ns
	if h.Flags&FlagHasKeyID != 0 {
		if len(buf)-off < 2 {
			return nil, 0, ErrTruncated
		}
		kl := binary.BigEndian.Uint16(buf[off : off+2])
		off += 2
		if len(buf)-off < int(kl) {
			return nil, 0, ErrTruncated
		}
		h.KeyID = buf[off : off+int(kl)]
		off += int(kl)
	}
	return h, off, nil
}

// HasContext reports whether the envelope carries a structured Context.
func (h *Header) HasContext() bool { return h.Flags&FlagHasContext != 0 }

// HasCommitment reports whether the envelope carries a key-commitment tag.
func (h *Header) HasCommitment() bool { return h.Flags&FlagHasCommitment != 0 }

// HasKeyID reports whether the envelope carries a key identifier.
func (h *Header) HasKeyID() bool { return h.Flags&FlagHasKeyID != 0 }

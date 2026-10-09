package envelope

import (
	"encoding/binary"
	"errors"
)

const (
	Magic       = "CRYPTKIT"
	Version     = 0x01
	MagicLen    = 8
	FixedHdrLen = 16 // magic + ver + alg + kdf + flags + kdfParamsLen
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
}

// Marshal writes the header bytes that will also serve as AEAD associated data.
func (h *Header) Marshal() []byte {
	out := make([]byte, 0, FixedHdrLen+len(h.KDFParams)+len(h.Nonce))
	out = append(out, Magic...)
	out = append(out, h.Version, byte(h.Algorithm), byte(h.KDF), h.Flags)
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(h.KDFParams)))
	out = append(out, l[:]...)
	out = append(out, h.KDFParams...)
	out = append(out, h.Nonce...)
	return out
}

// ParseHeader reads a header from the front of buf, returning the header
// and the offset where ciphertext begins.
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
	return h, off, nil
}

package envelope

import "errors"

var (
	ErrTooShort = errors.New("cryptkit: envelope too short")
)

// View is a parsed envelope: header, commitment (optional), ciphertext.
// It is produced by one parser so callers never compute offsets by hand.
type View struct {
	Header     *Header
	HeaderRaw  []byte // exact header bytes (used as AAD)
	Commitment []byte // nil if envelope has no commitment
	Ciphertext []byte // includes AEAD tag
}

// ParseView parses a full envelope. commitmentLen is the number of bytes
// the caller expects the commitment to occupy when the flag is set (0 means
// the caller doesn't know / doesn't require it).
func ParseView(blob []byte, commitmentLen int) (*View, error) {
	hdr, hdrEnd, err := ParseHeader(blob)
	if err != nil {
		return nil, err
	}
	v := &View{
		Header:    hdr,
		HeaderRaw: blob[:hdrEnd],
	}
	off := hdrEnd
	if hdr.HasCommitment() {
		if commitmentLen <= 0 {
			return nil, ErrTooShort
		}
		if off+commitmentLen > len(blob) {
			return nil, ErrTooShort
		}
		v.Commitment = blob[off : off+commitmentLen]
		off += commitmentLen
	}
	if off > len(blob) {
		return nil, ErrTooShort
	}
	v.Ciphertext = blob[off:]
	return v, nil
}

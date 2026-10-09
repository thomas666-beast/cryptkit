package cipher

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/thomas666-beast/cryptkit/envelope"
)

const DefaultChunkSize = 64 * 1024

// StreamOptions extends Options for chunked streaming.
type StreamOptions struct {
	Options
	ChunkSize    int
	NonceDeriver NonceDeriver
}

func (o StreamOptions) chunkSize() int {
	if o.ChunkSize <= 0 {
		return DefaultChunkSize
	}
	return o.ChunkSize
}

func (o StreamOptions) deriver() NonceDeriver {
	if o.NonceDeriver != nil {
		return o.NonceDeriver
	}
	return DefaultNonceDeriver
}

func (o StreamOptions) buildHeaderAAD(hdrBytes []byte) ([]byte, error) {
	return o.Options.buildAAD(hdrBytes)
}

func (o StreamOptions) writeHeaderAndCommitment(w io.Writer, key []byte, hdr *envelope.Header) (hdrBytes, hdrAAD []byte, err error) {
	hdrBytes = hdr.Marshal()
	if _, err = w.Write(hdrBytes); err != nil {
		return
	}
	if hdr.HasCommitment() {
		var c []byte
		c, err = computeCommitment(key, hdrBytes, o.Context)
		if err != nil {
			return
		}
		if _, err = w.Write(c); err != nil {
			return
		}
	}
	hdrAAD, err = o.buildHeaderAAD(hdrBytes)
	return
}

// EncryptStream reads plaintext from r and writes one envelope to w.
func EncryptStream(w io.Writer, r io.Reader, key []byte, opts StreamOptions) error {
	alg := opts.alg()
	info, ok := Lookup(alg)
	if !ok {
		return ErrUnsupported
	}
	aead, err := newAEAD(key, alg)
	if err != nil {
		return err
	}

	base := opts.Nonce
	if len(base) == 0 {
		base = make([]byte, info.NonceSize)
		if _, err := io.ReadFull(opts.rand(), base); err != nil {
			return err
		}
	} else if len(base) != info.NonceSize {
		return errors.New("cryptkit: nonce length mismatch")
	}

	var flags uint8
	if opts.hasContext() {
		flags |= envelope.FlagHasContext
	}
	if opts.RequireCommitment {
		flags |= envelope.FlagHasCommitment
	}
	if len(opts.KeyID) > 0 {
		flags |= envelope.FlagHasKeyID
	}

	hdr := &envelope.Header{
		Version:   envelope.Version,
		Algorithm: alg,
		KDF:       envelope.KDFNone,
		Flags:     flags,
		Nonce:     base,
		KeyID:     opts.KeyID,
	}

	_, hdrAAD, err := opts.writeHeaderAndCommitment(w, key, hdr)
	if err != nil {
		return err
	}

	cs := opts.chunkSize()
	deriver := opts.deriver()
	buf := make([]byte, cs)
	var index uint64

	for {
		n, rerr := io.ReadFull(r, buf)
		final := rerr == io.EOF || rerr == io.ErrUnexpectedEOF
		if rerr != nil && !final {
			return rerr
		}
		if n == 0 && final {
			nonce := deriver(base, index, info.NonceSize)
			aad := chunkIndexAAD(hdrAAD, index, true)
			ct := aead.Seal(nil, nonce, nil, aad)
			if _, err := w.Write(ct); err != nil {
				return err
			}
			return nil
		}
		nonce := deriver(base, index, info.NonceSize)
		aad := chunkIndexAAD(hdrAAD, index, final)
		ct := aead.Seal(nil, nonce, buf[:n], aad)
		if _, err := w.Write(ct); err != nil {
			return err
		}
		if final {
			return nil
		}
		index++
	}
}

// DecryptStream reads an envelope from r and writes plaintext to w.
func DecryptStream(w io.Writer, r io.Reader, key []byte, opts StreamOptions) error {
	hdrBytes, hdr, err := readStreamHeader(r)
	if err != nil {
		return err
	}
	info, ok := Lookup(hdr.Algorithm)
	if !ok {
		return ErrUnsupported
	}
	aead, err := newAEAD(key, hdr.Algorithm)
	if err != nil {
		return err
	}

	if hdr.HasCommitment() {
		var cbuf [commitLen]byte
		if _, err := io.ReadFull(r, cbuf[:]); err != nil {
			return err
		}
		if !verifyCommitment(key, hdrBytes, cbuf[:], opts.Context) {
			return ErrCommitCheck
		}
	} else if opts.RequireCommitment {
		return ErrCommitCheck
	}

	if hdr.HasContext() && !opts.hasContext() {
		return ErrContextCheck
	}

	hdrAAD, err := opts.buildHeaderAAD(hdrBytes)
	if err != nil {
		return err
	}
	deriver := opts.deriver()

	cs := opts.chunkSize()
	ctBuf := make([]byte, cs+aead.Overhead())
	var index uint64

	for {
		n, rerr := io.ReadFull(r, ctBuf)
		if rerr == io.EOF {
			return ErrTruncatedChunk
		}
		final := rerr == io.ErrUnexpectedEOF
		if rerr != nil && !final {
			return rerr
		}
		nonce := deriver(hdr.Nonce, index, info.NonceSize)
		aad := chunkIndexAAD(hdrAAD, index, final)
		pt, err := aead.Open(nil, nonce, ctBuf[:n], aad)
		if err != nil {
			return ErrDecrypt
		}
		if len(pt) > 0 {
			if _, err := w.Write(pt); err != nil {
				return err
			}
		}
		if final {
			var probe [1]byte
			_, terr := io.ReadFull(r, probe[:])
			if terr == nil {
				return ErrTrailingBytes
			}
			if !errors.Is(terr, io.EOF) && !errors.Is(terr, io.ErrUnexpectedEOF) {
				return terr
			}
			return nil
		}
		index++
	}
}

func readStreamHeader(r io.Reader) ([]byte, *envelope.Header, error) {
	head := make([]byte, envelope.FixedHdrLen)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, nil, err
	}
	alg := envelope.Algorithm(head[envelope.MagicLen+1])
	info, ok := Lookup(alg)
	if !ok {
		return nil, nil, ErrUnsupported
	}
	kdfLen := binary.BigEndian.Uint32(head[envelope.MagicLen+4 : envelope.MagicLen+8])
	rest := make([]byte, int(kdfLen)+info.NonceSize)
	if _, err := io.ReadFull(r, rest); err != nil {
		return nil, nil, err
	}
	// keyID section (optional) - read if flag bit 0x04 is set
	flags := head[envelope.MagicLen+3]
	full := append(head, rest...)
	if flags&envelope.FlagHasKeyID != 0 {
		var kl [2]byte
		if _, err := io.ReadFull(r, kl[:]); err != nil {
			return nil, nil, err
		}
		idLen := binary.BigEndian.Uint16(kl[:])
		id := make([]byte, idLen)
		if _, err := io.ReadFull(r, id); err != nil {
			return nil, nil, err
		}
		full = append(full, kl[:]...)
		full = append(full, id...)
	}
	hdr, _, err := envelope.ParseHeader(full)
	if err != nil {
		return nil, nil, err
	}
	return full, hdr, nil
}

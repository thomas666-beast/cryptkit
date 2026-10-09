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
    ChunkSize    int           // 0 => DefaultChunkSize
    NonceDeriver NonceDeriver  // nil => DefaultNonceDeriver
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

// EncryptStream reads plaintext from r and writes one envelope to w.
// Memory usage is O(chunkSize), independent of stream length.
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

    hdr := &envelope.Header{
        Version:   envelope.Version,
        Algorithm: alg,
        KDF:       envelope.KDFNone,
        Nonce:     base,
    }
    hdrBytes := hdr.Marshal()
    if _, err := w.Write(hdrBytes); err != nil {
        return err
    }
    hdrAAD := append(append([]byte{}, hdrBytes...), opts.AssociatedData...)

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
            // Emit a zero-length final chunk so decryptors know EOF explicitly.
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
    // We must know the header size to slice it out. Parse incrementally.
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
    hdrAAD := append(append([]byte{}, hdrBytes...), opts.AssociatedData...)
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
            return nil
        }
        index++
    }
}

func readStreamHeader(r io.Reader) ([]byte, *envelope.Header, error) {
    // Read enough to cover fixed header + max nonce, then parse.
    head := make([]byte, envelope.FixedHdrLen)
    if _, err := io.ReadFull(r, head); err != nil {
        return nil, nil, err
    }
    // Peek algorithm to know nonce size.
    alg := envelope.Algorithm(head[envelope.MagicLen+1])
    info, ok := Lookup(alg)
    if !ok {
        return nil, nil, ErrUnsupported
    }
    // KDF params length
    kdfLen := binary.BigEndian.Uint32(head[envelope.MagicLen+4 : envelope.MagicLen+8])
    rest := make([]byte, int(kdfLen)+info.NonceSize)
    if _, err := io.ReadFull(r, rest); err != nil {
        return nil, nil, err
    }
    full := append(head, rest...)
    hdr, _, err := envelope.ParseHeader(full)
    if err != nil {
        return nil, nil, err
    }
    return full, hdr, nil
}

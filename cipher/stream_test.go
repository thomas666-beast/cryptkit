package cipher_test

import (
    "bytes"
    "testing"

    "github.com/thomas666-beast/cryptkit/cipher"
)

func TestStreamRoundTrip(t *testing.T) {
    key := bytes.Repeat([]byte{0x11}, 32)
    for _, size := range []int{0, 1, 100, 64 * 1024, 200 * 1024} {
        msg := bytes.Repeat([]byte("A"), size)
        var enc bytes.Buffer
        if err := cipher.EncryptStream(&enc, bytes.NewReader(msg), key, cipher.StreamOptions{}); err != nil {
            t.Fatalf("size %d: enc: %v", size, err)
        }
        var dec bytes.Buffer
        if err := cipher.DecryptStream(&dec, &enc, key, cipher.StreamOptions{}); err != nil {
            t.Fatalf("size %d: dec: %v", size, err)
        }
        if !bytes.Equal(dec.Bytes(), msg) {
            t.Fatalf("size %d: mismatch", size)
        }
    }
}

func TestStreamTamperFails(t *testing.T) {
    key := bytes.Repeat([]byte{0x11}, 32)
    msg := bytes.Repeat([]byte("B"), 150_000)
    var enc bytes.Buffer
    _ = cipher.EncryptStream(&enc, bytes.NewReader(msg), key, cipher.StreamOptions{})
    b := enc.Bytes()
    b[len(b)/2] ^= 0x01
    var dec bytes.Buffer
    if err := cipher.DecryptStream(&dec, bytes.NewReader(b), key, cipher.StreamOptions{}); err == nil {
        t.Fatal("expected failure on tampered stream")
    }
}

package cipher_test

import (
	"bytes"
	"testing"

	"github.com/thomas666-beast/cryptkit/cipher"
	"github.com/thomas666-beast/cryptkit/context"
	"github.com/thomas666-beast/cryptkit/envelope"
)

func benchKey() []byte { return bytes.Repeat([]byte{0x42}, 32) }

func BenchmarkEncryptBytes(b *testing.B) {
	key := benchKey()
	msg := bytes.Repeat([]byte("A"), 4096)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cipher.Encrypt(key, msg, cipher.Options{Algorithm: envelope.AlgXChaCha20Poly1305})
	}
}

func BenchmarkEncryptWithContextAndCommit(b *testing.B) {
	key := benchKey()
	msg := bytes.Repeat([]byte("A"), 4096)
	ctx := context.Context{Purpose: "bench", Subject: "b:1"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cipher.Encrypt(key, msg, cipher.SecureOptions(ctx))
	}
}

func BenchmarkStream1MiB(b *testing.B) {
	key := benchKey()
	msg := bytes.Repeat([]byte("A"), 1<<20)
	b.SetBytes(int64(len(msg)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var out bytes.Buffer
		_ = cipher.EncryptStream(&out, bytes.NewReader(msg), key, cipher.StreamOptions{})
	}
}

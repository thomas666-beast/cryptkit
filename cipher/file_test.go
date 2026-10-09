package cipher_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/thomas666-beast/cryptkit/cipher"
)

func TestFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.bin")
	enc := filepath.Join(dir, "src.enc")
	dec := filepath.Join(dir, "src.dec")
	content := []byte("file-level round trip test content")
	if err := os.WriteFile(src, content, 0o600); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if err := cipher.EncryptFile(src, enc, key, cipher.FileOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := cipher.DecryptFile(enc, dec, key, cipher.FileOptions{}); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(dec)
	if string(got) != string(content) {
		t.Fatalf("mismatch: %q", got)
	}
}

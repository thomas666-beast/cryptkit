package kdf_test

import (
	"bytes"
	"testing"

	"github.com/thomas666-beast/cryptkit/kdf"
)

func TestKDFs(t *testing.T) {
	specs := []kdf.Spec{
		kdf.Argon2idSpec(8*1024, 1, 1),
		kdf.ScryptSpec(1<<14, 8, 1),
		kdf.HKDFSpec([]byte("ctx")),
	}
	for _, s := range specs {
		a, err := kdf.Derive(s, []byte("pw"), []byte("salt"), 32)
		if err != nil {
			t.Fatalf("%s: %v", s.Name, err)
		}
		b, _ := kdf.Derive(s, []byte("pw"), []byte("salt"), 32)
		if !bytes.Equal(a, b) {
			t.Fatalf("%s: non-deterministic", s.Name)
		}
		c, _ := kdf.Derive(s, []byte("pw2"), []byte("salt"), 32)
		if bytes.Equal(a, c) {
			t.Fatalf("%s: same output for different passwords", s.Name)
		}
	}
}

package cipher_test

import (
	"bytes"
	"fmt"

	"github.com/thomas666-beast/cryptkit/cipher"
	"github.com/thomas666-beast/cryptkit/context"
	"github.com/thomas666-beast/cryptkit/keys"
)

func ExampleEncrypt() {
	key, _ := keys.Generate(32, nil)
	ct, _ := cipher.Encrypt(key, []byte("hello"), cipher.DefaultOptions())
	pt, _ := cipher.Decrypt(key, ct, cipher.Options{})
	fmt.Println(string(pt))
	// Output: hello
}

func ExampleSecureOptions() {
	key := bytes.Repeat([]byte{0x42}, 32)
	ctx := context.Context{Purpose: "backup", Subject: "user:42"}

	ct, _ := cipher.Encrypt(key, []byte("secret"), cipher.SecureOptions(ctx))
	pt, _ := cipher.Decrypt(key, ct, cipher.Options{
		Context:           ctx,
		RequireCommitment: true,
	})
	fmt.Println(string(pt))
	// Output: secret
}

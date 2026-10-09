package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/thomas666-beast/cryptkit/cipher"
	ckctx "github.com/thomas666-beast/cryptkit/context"
	"github.com/thomas666-beast/cryptkit/keys"
	"github.com/thomas666-beast/cryptkit/passgen"
	"github.com/thomas666-beast/cryptkit/password"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "enc":
		cmdEnc(os.Args[2:])
	case "dec":
		cmdDec(os.Args[2:])
	case "hash":
		cmdHash(os.Args[2:])
	case "verify":
		cmdVerify(os.Args[2:])
	case "gen":
		cmdGen(os.Args[2:])
	case "genphrase":
		cmdGenPhrase(os.Args[2:])
	case "keygen":
		cmdKeygen(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `cryptkit — encrypt, decrypt, hash, verify, generate

Usage:
  cryptkit enc    -k <keyfile> -i <in> -o <out> [--purpose P --subject S]
  cryptkit dec    -k <keyfile> -i <in> -o <out> [--purpose P --subject S]
  cryptkit hash   -p <password>
  cryptkit verify -p <password> -H <hash>
  cryptkit gen    [--length N] [--ambiguous-free]
  cryptkit genphrase [--words N] [--sep -]
  cryptkit keygen [-o <keyfile>]

Key file accepts hex or base64 text, or raw bytes.`)
}

func ctxFromFlags(purpose, subject, origin string) ckctx.Context {
	if purpose == "" || subject == "" {
		return ckctx.Context{}
	}
	return ckctx.Context{
		Purpose: purpose,
		Subject: subject,
		Origin:  origin,
		Epoch:   uint64(time.Now().Unix()),
	}
}

func cmdEnc(args []string) {
	fs := flag.NewFlagSet("enc", flag.ExitOnError)
	key := fs.String("k", "", "key file")
	in := fs.String("i", "", "input file")
	out := fs.String("o", "", "output file")
	purpose := fs.String("purpose", "", "context purpose (required for CBL)")
	subject := fs.String("subject", "", "context subject (required for CBL)")
	origin := fs.String("origin", "", "context origin")
	fs.Parse(args)

	k := mustKey(*key)
	opts := cipher.FileOptions{
		StreamOptions: cipher.StreamOptions{
			Options: cipher.Options{
				Context:           ctxFromFlags(*purpose, *subject, *origin),
				RequireCommitment: true,
			},
		},
	}
	if err := cipher.EncryptFile(*in, *out, k, opts); err != nil {
		fatal(err)
	}
	fmt.Println("encrypted:", *out)
}

func cmdDec(args []string) {
	fs := flag.NewFlagSet("dec", flag.ExitOnError)
	key := fs.String("k", "", "key file")
	in := fs.String("i", "", "input file")
	out := fs.String("o", "", "output file")
	purpose := fs.String("purpose", "", "context purpose")
	subject := fs.String("subject", "", "context subject")
	fs.Parse(args)

	k := mustKey(*key)
	opts := cipher.FileOptions{
		StreamOptions: cipher.StreamOptions{
			Options: cipher.Options{
				Context:           ctxFromFlags(*purpose, *subject, ""),
				RequireCommitment: true,
			},
		},
	}
	if err := cipher.DecryptFile(*in, *out, k, opts); err != nil {
		fatal(err)
	}
	fmt.Println("decrypted:", *out)
}

func cmdHash(args []string) {
	fs := flag.NewFlagSet("hash", flag.ExitOnError)
	pw := fs.String("p", "", "password")
	fs.Parse(args)
	h, err := password.HashPassword(*pw)
	if err != nil {
		fatal(err)
	}
	fmt.Println(h)
}

func cmdVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	pw := fs.String("p", "", "password")
	h := fs.String("H", "", "hash")
	fs.Parse(args)
	if err := password.VerifyPassword(*pw, *h); err != nil {
		fatal(err)
	}
	fmt.Println("OK")
}

func cmdGen(args []string) {
	fs := flag.NewFlagSet("gen", flag.ExitOnError)
	length := fs.Int("length", 24, "password length")
	ambig := fs.Bool("ambiguous-free", false, "exclude 0/O/1/l/I")
	fs.Parse(args)

	cs := passgen.DefaultCharset()
	if *ambig {
		cs = cs.AmbiguousFree()
	}
	pw, err := passgen.Generate(passgen.GenOptions{
		Length:          *length,
		Charset:         cs,
		EnsureEachClass: true,
	})
	if err != nil {
		fatal(err)
	}
	fmt.Println(pw)
}

func cmdGenPhrase(args []string) {
	fs := flag.NewFlagSet("genphrase", flag.ExitOnError)
	words := fs.Int("words", 6, "number of words")
	sep := fs.String("sep", "-", "separator")
	fs.Parse(args)
	pp, err := passgen.GeneratePassphrase(*words, *sep, nil, nil)
	if err != nil {
		fatal(err)
	}
	fmt.Println(pp)
}

func cmdKeygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("o", "cryptkit.key", "output file")
	fs.Parse(args)
	k, err := keys.Generate(32, nil)
	if err != nil {
		fatal(err)
	}
	if err := os.WriteFile(*out, []byte(keys.ToHex(k)+"\n"), 0o600); err != nil {
		fatal(err)
	}
	fmt.Println("wrote:", *out)
}

func mustKey(path string) []byte {
	if path == "" {
		fatal(fmt.Errorf("missing -k key file"))
	}
	raw, err := keys.FromFile(path)
	if err != nil {
		fatal(err)
	}
	s := strings.TrimSpace(string(raw))
	if b, err := keys.FromHex(s); err == nil && len(b) == 32 {
		return b
	}
	if b, err := keys.FromBase64(s); err == nil && len(b) == 32 {
		return b
	}
	if len(raw) == 32 {
		return raw
	}
	fatal(fmt.Errorf("key file must decode to 32 bytes"))
	return nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

// silence unused import
var _ = context.Background

func cmdRewrap(args []string) {
	fs := flag.NewFlagSet("rewrap", flag.ExitOnError)
	oldKeyPath := fs.String("old", "", "old key file")
	newKeyPath := fs.String("new", "", "new key file")
	in := fs.String("i", "", "input file")
	out := fs.String("o", "", "output file")
	purpose := fs.String("purpose", "", "context purpose")
	subject := fs.String("subject", "", "context subject")
	origin := fs.String("origin", "", "context origin")
	fs.Parse(args)

	oldKey := mustKey(*oldKeyPath)
	newKey := mustKey(*newKeyPath)
	ctx := ctxFromFlags(*purpose, *subject, *origin)

	opts := cipher.FileOptions{
		StreamOptions: cipher.StreamOptions{
			Options: cipher.Options{
				Context:           ctx,
				RequireCommitment: true,
			},
		},
		Overwrite: true,
	}

	// decrypt to temp, re-encrypt
	tmp, err := os.CreateTemp("", "cryptkit-rewrap-*")
	if err != nil {
		fatal(err)
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	if err := cipher.DecryptFile(*in, tmp.Name(), oldKey, opts); err != nil {
		fatal(err)
	}
	if err := cipher.EncryptFile(tmp.Name(), *out, newKey, opts); err != nil {
		fatal(err)
	}
	fmt.Println("rewrapped:", *out)
}

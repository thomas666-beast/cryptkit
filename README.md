# cryptkit

A general-purpose Go crypto library: encrypt/decrypt bytes, text, and files;
hash and verify passwords; generate secure passwords and passphrases.

**Learning project. Not audited. Do not use in production.**

## Install

    go get github.com/thomas666-beast/cryptkit

## Encrypt bytes

    key := must(keys.Generate(32, nil))
    ct, _ := cipher.Encrypt(key, []byte("secret"), cipher.Options{})
    pt, _ := cipher.Decrypt(key, ct, cipher.Options{})

## Encrypt a file (streaming, low memory)

    err := cipher.EncryptFile("db.sql", "db.sql.enc", key, cipher.FileOptions{})
    err  = cipher.DecryptFile("db.sql.enc", "db.sql", key, cipher.FileOptions{})

## Password hashing

    hash, _ := password.HashPassword("hunter2")
    err  := password.VerifyPassword("hunter2", hash)  // nil on success

## Generate passwords

    pw, _ := passgen.Generate(passgen.GenOptions{Length: 24, EnsureEachClass: true})
    pp, _ := passgen.GeneratePassphrase(6, "-", nil, nil)

## Customize everything

Every function takes an options struct. Supply `Rand`, `Algorithm`, `Nonce`,
`ChunkSize`, `NonceDeriver`, or register your own AEAD via `cipher.Register`.

## Features unique to cryptkit

- **Context-Binding Layer (CBL)** — every ciphertext is bound to a
  structured, mandatory context (purpose, subject, origin, epoch). Decryption
  with the wrong context fails, even with the right key.
- **Key Commitment** — explicit commitment tag defeats wrong-key
  decryption attempts before AEAD runs. Most Go crypto libraries don't.
- **No hard-coded algorithms** — AEADs live in a registry; add your own.
- **Pluggable entropy** — every function takes `Rand io.Reader`.
- **Built-in password generator** — random, passphrase, PIN.

## v0.4 highlights

- EnvelopeView — offset arithmetic centralized in one parser
- Fuzz tests — Decrypt never panics on arbitrary input
- Wycheproof vectors — AEAD wiring tested against Google's adversarial suite
- password.NeedsRehash — parameter drift detection
- keys.Keyring — multi-key rotation with DecryptWithKeyring
- CLI: rewrap command, context flags on enc/dec

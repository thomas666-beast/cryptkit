# cryptkit

A general-purpose Go crypto library: encrypt/decrypt bytes, text, and files;
hash and verify passwords; generate secure passwords and passphrases.

> **Learning project. Not audited. Do not use in production.**

## Install

    go get github.com/thomas666-beast/cryptkit

## Features

- **Encrypt / decrypt** bytes, streams, and files
- **Three AEADs** behind a **pluggable registry**
- **Context-Binding Layer** — structured, mandatory context bound to every ciphertext
- **Key commitment** — wrong-key attempts fail before AEAD runs
- **Chunked streaming** — bounded memory regardless of file size
- **Password hashing** — Argon2id (PHC format), bcrypt verification for migration
- **Password generator** — random, passphrase, PIN
- **Keyring** — multi-key with key IDs
- **Tamper-evident audit log** — hash-chained, HMAC-signed

## Quick start

### Encrypt bytes

```go
key, _ := keys.Generate(32, nil)
ct, _ := cipher.Encrypt(key, []byte("hello"), cipher.DefaultOptions())
pt, _ := cipher.Decrypt(key, ct, cipher.Options{})

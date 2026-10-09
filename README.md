# cryptkit

A general-purpose Go crypto library: encrypt/decrypt bytes, text, and files;
hash and verify passwords; generate secure passwords and passphrases.

> **Learning project. Not audited. Do not use in production.**

## Install

```bash
go get github.com/thomas666-beast/cryptkit
```

## Features

- **Encrypt / decrypt** bytes, streams, and files
- **Three AEADs** (AES-256-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305) behind a **pluggable registry**
- **Context-Binding Layer** — structured, mandatory context bound to every ciphertext
- **Key commitment** — wrong-key attempts fail before AEAD runs
- **Chunked streaming** — bounded memory regardless of file size
- **Password hashing** — Argon2id (PHC format), bcrypt verification for migration
- **Password generator** — random, passphrase (EFF wordlist), PIN
- **Keyring** — multi-key with key IDs, no trial decryption
- **Tamper-evident audit log** — hash-chained, HMAC-signed operation records

## Packages

| Package | Purpose |
|---|---|
| `cipher` | AEAD encrypt/decrypt (bytes, streams, files), key commitment, keyring |
| `envelope` | On-disk v1 format: header, flags, key ID, offsets |
| `context` | Context-Binding Layer: structured, canonical context |
| `keys` | Key generation, loading, keyring, key IDs |
| `kdf` | Argon2id, scrypt, HKDF behind a uniform `Spec` |
| `password` | Argon2id PHC hashing + bcrypt verification |
| `passgen` | Password / passphrase / PIN generation |
| `audit` | Tamper-evident, hash-chained operation log |

## Quick start

### Encrypt bytes

```go
key, _ := keys.Generate(32, nil)
ct, _ := cipher.Encrypt(key, []byte("hello"), cipher.DefaultOptions())
pt, _ := cipher.Decrypt(key, ct, cipher.Options{})
fmt.Println(string(pt)) // hello
```

### Encrypt a file (streaming, low memory)

```go
err := cipher.EncryptFile("db.sql", "db.sql.enc", key, cipher.FileOptions{})
err  = cipher.DecryptFile("db.sql.enc", "db.sql", key, cipher.FileOptions{})
```

### Password hashing

```go
hash, _ := password.HashPassword("hunter2")
err  := password.VerifyPassword("hunter2", hash) // nil on success
```

### Password generation

```go
pw, _ := passgen.Generate(passgen.GenOptions{
    Length:          24,
    EnsureEachClass: true,
})
pp, _ := passgen.GeneratePassphrase(6, "-", nil, nil)
pin, _ := passgen.GeneratePIN(6, nil)
```

### Context binding — cryptkit's unique layer

```go
ctx := context.Context{Purpose: "backup", Subject: "user:42"}

ct, _ := cipher.Encrypt(key, data, cipher.SecureOptions(ctx))
pt, _ := cipher.Decrypt(key, ct, cipher.Options{
    Context:           ctx,
    RequireCommitment: true,
})
```

A different `Subject` — even with the correct key — fails decryption.

### Keyring

```go
ring := keys.NewKeyring()
ring.Add("old", oldKey, false)
ring.Add("new", newKey, true)

ct, _ := cipher.Encrypt(newKey, data, cipher.Options{
    KeyID: keys.KeyIDBytes(newKey),
})

pt, which, err := cipher.DecryptWithKeyring(ring, ct, cipher.Options{})
```

### Audit log

```go
log, _ := audit.NewFileLog("audit.jsonl", logKey)
defer log.Close()

_, _ = cipher.Encrypt(key, data, cipher.Options{
    Audit: log,
})

recs, _ := audit.ReadAll(file)
if err := audit.Verify(recs, logKey); err != nil {
    // log was tampered with
}
```

## CLI

The `cmd/cryptkit` binary exposes:

```
cryptkit enc    -k <keyfile> -i <in> -o <out> [--purpose P --subject S]
cryptkit dec    -k <keyfile> -i <in> -o <out> [--purpose P --subject S]
cryptkit hash   -p <password>
cryptkit verify -p <password> -H <hash>
cryptkit gen    [--length N] [--ambiguous-free]
cryptkit genphrase [--words N] [--sep -]
cryptkit keygen [-o <keyfile>]
cryptkit rewrap -old <keyfile> -new <keyfile> -i <in> -o <out>
```

Build:

```bash
go build -o cryptkit ./cmd/cryptkit
```

## Envelope format (v1)

```
[ magic 8 ][ ver 1 ][ alg 1 ][ kdf 1 ][ flags 1 ][ kdfLen 4 ]
[ kdfParams N ][ nonce M ][ keyIDLen 2 ][ keyID K ]
[ commitment 32? ][ ciphertext+tag ]
```

- `flags` bit 0 → Context present
- `flags` bit 1 → Commitment present
- `flags` bit 2 → Key ID present

All decryption paths go through `envelope.ParseView`, which returns the
three regions separately so callers never compute offsets by hand.

## Customization

Every function takes an options struct. Nothing is hard-coded:

- `Rand io.Reader` — inject your own entropy source
- `cipher.Register(...)` — add your own AEAD
- `Options.Algorithm` — pick any registered algorithm
- `Options.KeyID` — bind to a keyring entry
- `Options.Context` — structured context binding
- `StreamOptions.ChunkSize`, `NonceDeriver` — tune streaming

## Testing

```bash
go test ./... -race
go vet ./...
go test ./cipher/ -run Wycheproof -v
go test ./cipher/ -run '^$' -fuzz FuzzDecryptNeverPanics -fuzztime 30s
go test ./cipher/ -run '^$' -fuzz FuzzRoundTripWithContext -fuzztime 30s
```

Wycheproof vectors are fetched by CI; locally, place them at
`internal/testvec/wycheproof/`:

```bash
mkdir -p internal/testvec/wycheproof
curl -sL -o internal/testvec/wycheproof/aes_gcm_test.json \
  https://raw.githubusercontent.com/C2SP/wycheproof/master/testvectors_v1/aes_gcm_test.json
curl -sL -o internal/testvec/wycheproof/chacha20_poly1305_test.json \
  https://raw.githubusercontent.com/C2SP/wycheproof/master/testvectors_v1/chacha20_poly1305_test.json
```

## What this is

- A well-tested, race-clean, Wycheproof-verified implementation of standard
  primitives, composed into a coherent, opinionated format.
- A teaching tool: every public package has a `doc.go` and runnable
  `Example*` functions.

## What this isn't

- Audited. No external security review has been performed.
- A replacement for `age`, `Tink`, or `libsodium` in production.
- A new cryptographic primitive. It reuses `crypto/*` and `x/crypto`.

## License

MIT — see [LICENSE](LICENSE).

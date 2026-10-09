# Changelog

## v1.0.0 — stable learning release

First stable release. Library is tested, race-clean, and Wycheproof-verified.
It is a learning project and has not been audited.

- Packages: cipher, envelope, context, keys, kdf, password, passgen, audit
- CLI: enc, dec, hash, verify, gen, genphrase, keygen, rewrap
- Tests: unit, race, fuzz, Wycheproof vectors
- CI: vet, race, fuzz smoke, Wycheproof

## v0.6.0

- Key ID layer in the envelope header (flag bit 0x04)
- keys.KeyID / keys.KeyIDBytes
- cipher.DecryptWithKeyring selects by key ID, falls back to trial

## v0.5.0

- Tamper-evident audit log with hash chain and HMAC signatures
- audit.NewWriterLog, NewFileLog, OpenReaderLog, ReadAll, Verify

## v0.4.0

- EnvelopeView: single envelope parser, no hand-computed offsets
- Fuzz tests: Decrypt never panics on arbitrary input
- Wycheproof vectors for AES-GCM and ChaCha20-Poly1305
- password.NeedsRehash for parameter drift
- keys.Keyring, cipher.DecryptWithKeyring
- CLI: rewrap command

## v0.3.0

- Context-Binding Layer (structured, mandatory context)
- Key commitment tag (AEADs are not key-committing)
- CLI: enc, dec, hash, verify, gen, genphrase, keygen
- Benchmarks

## v0.2.0

- Streaming encryption (EncryptStream, DecryptStream)
- File encryption (EncryptFile, DecryptFile)
- Chunked AEAD with per-chunk nonce derivation
- Pluggable AEAD registry (cipher.Register)
- keys, kdf, passgen packages

## v0.1.0

- Initial: bytes encryption (AES-256-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305)
- Versioned envelope format
- password hashing (Argon2id, PHC format; bcrypt verification)

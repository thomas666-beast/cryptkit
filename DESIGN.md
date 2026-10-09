# cryptkit Design

## Goals
- General-purpose: bytes, text, files, streams.
- Algorithm-agile: envelope format survives algorithm upgrades.
- Misuse-resistant: safe defaults, hard to do the wrong thing.
- Library-first; CLI is a thin consumer.

## Non-goals
- Compatibility with age / JWE / libsodium.
- Inventing cryptographic primitives.
- Post-quantum (yet).

## Envelope format (v1)

All integers big-endian.

  Offset  Size  Field
  ------  ----  -----
       0     8  Magic: "CRYPTKIT"
       8     1  Format version (0x01)
       9     1  Algorithm ID
      10     1  KDF ID
      11     1  Flags (reserved, 0x00)
      12     4  KDF params length (N)
      16     N  KDF params (algorithm-specific)
    16+N    24  Nonce
   40+N     *   Ciphertext || Auth tag

### Algorithm IDs
  0x01  AES-256-GCM           (12-byte nonce, 16-byte tag)
  0x02  ChaCha20-Poly1305     (12-byte nonce, 16-byte tag)
  0x03  XChaCha20-Poly1305    (24-byte nonce, 16-byte tag)

### KDF IDs
  0x00  none            (key supplied directly)
  0x01  Argon2id        (params: m, t, p — each uint32)
  0x02  scrypt          (params: N, r, p — each uint32)
  0x03  HKDF-SHA256     (params: salt length + salt, info length + info)

### Associated data
The entire header (bytes 0..40+N) is passed as AEAD associated data.
This binds ciphertext to algorithm choice, KDF, and nonce — preventing
downgrade and header-swap attacks.

## Password hashing format (PHC-compatible)

  $cryptkit$argon2id$v=19$m=65536,t=3,p=4$<b64salt>$<b64hash>

  $cryptkit$bcrypt$<bcrypt-encoded>     (compat mode only)

## Error model
- All exported functions return `error`.
- Sentinel errors in each package (ErrDecrypt, ErrInvalidFormat, ErrWrongKey).
- Never leak timing info on password verification (use constant-time compare).

## Streaming (chunked AEAD)

For files / streams, plaintext is split into chunks of ChunkSize (default 64 KiB).

  chunk_i = AEAD.Seal(nonce_i, pt_i, aad_i)
  nonce_i = HMAC-SHA256(baseNonce, uint64_be(i))[:nonceSize]
  aad_i   = headerBytes || associatedData || uint64_be(i) || finalByte

- Chunk index in AAD prevents reordering / duplication.
- finalByte in AAD prevents silent truncation.
- Zero-length final chunk signals EOF explicitly.

## Registries (no hard-coded algorithms)

AEAD algorithms live in a registry (`cipher.Register`). Third parties can add
their own by calling Register in init(). No switch statement in the core.

## Password generator

passgen.Generate — random password with composable Charset.
passgen.GeneratePassphrase — wordlist-based, EFF short list embedded.
passgen.GeneratePIN — numeric.

All accept a `Rand io.Reader`, so callers can use HSM entropy or a
deterministic source in tests.

## Context-Binding Layer (CBL) — cryptkit's signature feature

Standard AEAD takes free-form Associated Data. Most libraries stop there.
cryptkit enforces a *structured, mandatory* Context:

    Purpose  — what this data is for      (mandatory)
    Subject  — who it belongs to          (mandatory)
    Origin   — where it was created       (optional)
    Epoch    — when it was created        (optional)
    Extra    — arbitrary key/value pairs  (optional)

The Context is canonicalized (deterministic byte encoding), hashed, and
included in the AEAD AAD. At decryption the caller MUST supply the same
Context; mismatch fails even if the key is correct.

This defeats:
- Ciphertext substitution (moving Alice's blob into Bob's slot)
- Cross-protocol replay (a token from service A replayed at service B)
- Domain confusion (a "backup" ciphertext used as a "session token")
- Silent downgrade (envelope claims context; caller must supply one)

## Key Commitment

AEADs are not key-committing. cryptkit adds an explicit commitment tag:

    commit = HMAC-SHA256(HKDF(key, "cryptkit/commitment/v1"),
                         headerBytes || SHA256(canonicalContext))

Stored immediately after the header. On decrypt, recomputed from the
caller's key and context and compared in constant time. Mismatch means
either the key is wrong or the context differs — before AEAD ever runs.

## Envelope layout (v1) — corrected

    [ header ][ commitment? ][ ciphertext+tag ]

- header: magic, version, alg, kdf, flags, kdfParamsLen, kdfParams, nonce
- commitment (32 bytes): present iff flag bit 1 is set
- ciphertext: AEAD output

The AAD for AEAD is header || rawAAD || canonicalContext. The commitment
tag is NOT part of AAD — it has its own purpose (key-commitment).

## EnvelopeView

All decryption paths go through envelope.ParseView, which returns the
three regions separately. No caller should compute offsets by hand.

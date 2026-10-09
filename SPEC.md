# cryptkit v1 — Format Specification

This document specifies the on-disk ciphertext format produced by cryptkit
v1.0. Any implementation that follows this document can interoperate with
cryptkit for the v1 format.

## 1. Notation

- All integers are big-endian.
- `u8`, `u16`, `u32`, `u64` mean unsigned integers of the given width in bits.
- Byte ranges are inclusive-exclusive: `[a, b)` means bytes `a..b-1`.
- Hex literals are prefixed with `0x`.

## 2. Envelope layout

A v1 envelope is a sequence of four regions, in order:

    [ header ][ commitment? ][ ciphertext+tag ]

The commitment region is present iff the header's `flags` bit 1 is set.
The ciphertext region is present always and includes the AEAD tag.

## 3. Header

    Offset  Size  Field
    ------  ----  -----
         0     8  magic          = "CRYPTKIT" (ASCII)
         8     1  version        = 0x01
         9     1  algorithm      (see §4)
        10     1  kdf            (see §5)
        11     1  flags          (see §6)
        12     4  kdfParamsLen   = N (u32)
        16     N  kdfParams      (KDF-specific, empty when kdf = 0x00)
     16+N     M  nonce          (M = algorithm's nonce size, see §4)
     16+N+M   2  keyIDLen       (u16) — present iff flags bit 2 set
     18+N+M   K  keyID          — present iff flags bit 2 set

The header length is `16 + N + M + (flags bit 2 ? 2 + K : 0)`.

The header bytes (exactly the header region, no commitment, no ciphertext)
are used as AEAD associated data, together with any caller-supplied
associated data and the canonical context (see §8).

## 4. Algorithm identifiers

    0x01  AES-256-GCM         nonce size 12, key size 32, tag size 16
    0x02  ChaCha20-Poly1305   nonce size 12, key size 32, tag size 16
    0x03  XChaCha20-Poly1305  nonce size 24, key size 32, tag size 16

The default algorithm when none is specified is 0x03.

## 5. KDF identifiers

    0x00  none      kdfParams empty
    0x01  Argon2id  kdfParams = 12 bytes: m (u32) || t (u32) || p (u32)
    0x02  scrypt    kdfParams = 12 bytes: N (u32) || r (u32) || p (u32)
    0x03  HKDF-SHA256 kdfParams = 2 (saltLen) || salt || 2 (infoLen) || info

`m` is memory in KiB. `t` is iterations. `p` is parallelism. This version
of cryptkit does not use the KDF field in its default Encrypt path; it is
reserved for future use and for callers that pre-derive keys.

## 6. Flags

    Bit 0 (0x01)  Context present
    Bit 1 (0x02)  Key commitment present
    Bit 2 (0x04)  Key ID present
    Bits 3-7      Reserved, MUST be zero

Readers MUST reject envelopes with reserved bits set (forward-compat
policy may change in a future version).

## 7. Key commitment

When flag bit 1 is set, the header is immediately followed by 32 bytes of
commitment:

    commitKey = HKDF-SHA256(ikm=key, salt=nil, info="cryptkit/commitment/v1",
                            L=32)
    ctxHash   = SHA-256(canonicalContext)      (32 bytes, only if context
                                                is present)
    commitment = HMAC-SHA256(key=commitKey,
                             msg=headerBytes || ctxHash)

If the envelope has no context, `ctxHash` is omitted.

On decryption, the commitment MUST be recomputed from the caller's key and
context and compared in constant time. A mismatch MUST abort before AEAD
verification.

## 8. Context canonicalization

A Context has the fields `Purpose` (string, required), `Subject` (string,
required), `Origin` (string, optional), `Epoch` (u64, optional), and
`Extra` (map<string, string>, optional).

Canonical form, UTF-8, in this exact order:

    "cryptkit-ctx-v1\n"
    "purpose=" || Purpose || "\n"
    "subject=" || Subject || "\n"
    "origin="  || Origin  || "\n"
    "epoch="   || be64(Epoch) || "\n"
    (for each key K in sorted(Extra)):
        "x-" || K || "=" || Extra[K] || "\n"

No escaping is performed. Callers MUST ensure field values do not contain
`\n`, since that would allow collisions. The library currently does not
enforce this; callers who accept arbitrary input should sanitize.

## 9. AAD

The AEAD associated data for the header is:

    headerBytes || callerAssociatedData || canonicalContext

`canonicalContext` is included only if the context flag is set. This
combination is called the `headerAAD`.

## 10. Ciphertext

For single-shot encryption, the ciphertext region is:

    AEAD.Seal(nonce, plaintext, headerAAD)          (tag appended by AEAD)

For streaming, the ciphertext region is one or more chunks:

    chunk_i = AEAD.Seal(nonce_i, pt_i, chunkAAD_i)

where:

    nonce_i = HMAC-SHA256(key=baseNonce, msg=be64(i))[:M]
    chunkAAD_i = headerAAD || be64(i) || (i == last ? 0x01 : 0x00)

Chunk index `i` starts at 0. The final chunk is flagged with byte 0x01.
A zero-length final chunk is emitted to mark EOF explicitly.

Memory use during encryption and decryption is bounded by chunk size,
which defaults to 64 KiB but is caller-configurable.

## 11. Decryption procedure

1. Read the fixed header prefix (16 bytes). Verify magic and version.
2. Read kdfParams (length from step 1), nonce (algorithm-dependent), and
   keyID if flag bit 2 is set.
3. If flag bit 1 is set, read 32 bytes of commitment. Recompute it from
   the caller's key and context; constant-time compare; abort on mismatch.
4. If context flag is set and caller did not supply a context, abort.
5. Compute headerAAD as in §9.
6. For single-shot: AEAD.Open(nonce, ciphertext, headerAAD). Abort on tag
   failure.
7. For streaming: read chunks until the final chunk flag is seen. Verify
   each chunk with its own AAD. Abort on any tag failure. Reject any bytes
   after the final chunk.

## 12. Interoperability notes

- The `keyID` field is non-secret. It is the truncated SHA-256 of the key.
  Nothing about the plaintext or ciphertext can be inferred from it.
- Envelopes are self-describing: an implementation can decrypt a v1 file
  without out-of-band algorithm information, given only the key and the
  context (if any).
- The `kdfParams` field is currently unused by cryptkit's default
  Encrypt path. Implementations that write it must also document how the
  key was derived. Reads of unknown KDF IDs MUST fail closed.

## 13. Versioning

The version byte is 0x01. A future version that changes the layout,
algorithm IDs, or semantics must increment it. Readers MUST refuse to
decrypt envelopes whose version they do not understand.

Forward-compatible additions that do not change the layout may reuse
currently-reserved flag bits in a minor version. Readers MUST ignore
unknown flag bits only if a version negotiation mechanism is added;
until then, unknown flags SHOULD be treated as an error.

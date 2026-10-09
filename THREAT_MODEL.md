# cryptkit Threat Model

This document describes what cryptkit defends against, what it does not,
and the assumptions a caller must satisfy to get the stated guarantees.

## 1. What cryptkit is

A library that encrypts bytes, streams, and files using standard AEADs,
hashes passwords with Argon2id, generates passwords and passphrases, and
records cryptographic operations in a tamper-evident log.

It is not a protocol, not a network service, and not a key management
system. It is a set of building blocks.

## 2. Assets protected

- **Confidentiality** of plaintext encrypted with cryptkit
- **Integrity** of ciphertext (any modification is detected)
- **Authenticity** of the key used (key commitment)
- **Binding** of ciphertext to its declared context (purpose, subject)
- **Integrity** of the audit log (detects tampering)
- **Password verifier strength** (Argon2id with tunable cost)

## 3. Adversary capabilities considered

The adversary is assumed to:

- Observe all ciphertexts, headers, and key IDs
- Modify, reorder, truncate, or replay ciphertexts
- Control network and file system where ciphertext is stored
- Attempt offline brute force against password hashes
- Know the cryptkit format and all public parameters
- Not know the key

The adversary is **not** assumed to:

- Break AES, ChaCha20, Poly1305, SHA-256, HMAC, Argon2id, scrypt, or HKDF
- Compromise the host's CSPRNG (`crypto/rand`)
- Have access to the key material at runtime
- Have root on the host executing cryptkit

## 4. Attacks defended against

### 4.1 Ciphertext tampering
Every ciphertext carries an AEAD tag (16 bytes). Any modification causes
`ErrDecrypt`. Both single-shot and streaming modes verify per-chunk tags.

### 4.2 Chunk reordering and truncation
Each chunk's AAD binds its index and a final-chunk flag. Reordering
chunks or truncating the stream fails AEAD verification.

### 4.3 Trailing garbage after streaming decryption
Streaming decryption reads one byte past the final chunk. If the byte
exists, `ErrTrailingBytes` is returned.

### 4.4 Ciphertext substitution
The Context-Binding Layer binds every ciphertext to a caller-supplied
Context (purpose, subject, optionally origin, epoch, extra). A ciphertext
produced under one context fails decryption under another, even with the
correct key.

### 4.5 Cross-protocol replay
Because the context includes a purpose string, a ciphertext labeled
`"session-token"` cannot be decrypted as `"backup"`. Applications that
include application-specific strings in `Purpose` inherit this property.

### 4.6 Wrong-key decryption
The key commitment tag binds the ciphertext to the key. Wrong-key attempts
fail before AEAD verification, avoiding ambiguous error channels.

### 4.7 Audit log tampering
The audit log is a hash chain: each record includes the SHA-256 of the
previous record and an HMAC-SHA256 signature under a log key. Modifying,
deleting, or reordering any record breaks the chain and is detected by
`audit.Verify`.

### 4.8 Nonce reuse in streaming
Per-chunk nonces are derived as `HMAC-SHA256(baseNonce, be64(i))`. The
base nonce is random per stream. Nonce reuse requires either CSPRNG
failure or reusing the same key with the same base nonce, which the
library does not do.

## 5. Attacks NOT defended against

### 5.1 Key compromise
If the key leaks, all past and future ciphertexts are readable. cryptkit
does not forward-secure.

### 5.2 Plaintext leakage outside AEAD
Metadata (header fields, key ID, ciphertext length, chunk count, timing)
is observable. If the length of a plaintext leaks information, cryptkit
does not hide it.

### 5.3 Context field injection
Context field values are not escaped. A caller that passes user-controlled
strings containing `\n` into `Purpose`, `Subject`, `Origin`, or `Extra`
values can create canonicalization collisions. Callers MUST sanitize
input or use fixed-format values (e.g., `"user:" + id`, not raw user text).

### 5.4 Side channels
The library does not attempt to hide:
- Timing of encryption/decryption (though AEAD verification is
  constant-time)
- Cache effects of AES-GCM (hardware-accelerated on most platforms;
  ChaCha20-Poly1305 is constant-time by design)
- Memory access patterns

Callers requiring side-channel resistance should prefer XChaCha20-Poly1305
and audit their own access patterns.

### 5.5 Password hashing after compromise
If a password hash and its parameters leak, Argon2id resists offline
brute force only insofar as the parameters are strong enough on the
attacker's hardware. The library exposes `NeedsRehash` to detect parameter
drift, but does not enforce rehash policy.

### 5.6 Malicious library input
`cipher.Decrypt`, `cipher.DecryptStream`, and `audit.Verify` are tested
with fuzzing against arbitrary input and never panic. They may return
errors with attacker-influenced content; callers should not assume error
strings are safe to display verbatim.

### 5.7 Key management
cryptkit stores keys as raw bytes. It does not:
- Encrypt keys at rest with a passphrase
- Integrate with OS keystores (macOS Keychain, Windows DPAPI, Linux
  Secret Service)
- Support HSMs or PKCS#11

Callers needing these must wrap cryptkit.

### 5.8 Denial of service
Streaming decryption allocates `chunkSize + AEAD.Overhead()` per call.
Chunk size is caller-controlled. A caller that accepts arbitrary chunk
sizes from untrusted input could be induced to allocate large buffers;
callers should bound chunk size to a reasonable maximum.

## 6. Assumptions the caller must satisfy

1. **Keys are secret.** cryptkit cannot protect a leaked key.
2. **Keys are high-entropy.** Use `keys.Generate` or derive from a strong
   source. Do not use human-chosen strings directly as keys; use `kdf`.
3. **Context fields are controlled.** Do not pass user input verbatim.
4. **Nonces are unique per (key, algorithm) pair for single-shot mode.**
   The library generates random nonces and, for XChaCha20-Poly1305, the
   24-byte nonce makes collision astronomically unlikely. Callers who
   supply their own nonce take responsibility for uniqueness.
5. **The host is not compromised.** cryptkit cannot defend against an
   attacker with code execution on the host.
6. **`crypto/rand` is trustworthy.** The library delegates all randomness
   to it (or to a caller-supplied `Rand`).

## 7. Out-of-scope

- Post-quantum resistance
- Forward secrecy
- Threshold cryptography
- Group messaging
- Identity-based encryption
- Secure multi-party computation

## 8. Verifying these claims

Each defensive property above is exercised by at least one test:

| Claim | Test |
|---|---|
| Tamper detection | `TestTamperedCiphertextFails` |
| Streaming tamper | `TestStreamTamperFails` |
| Context binding | `TestWrongContextFails` |
| Key commitment | `TestWrongKeyFailsCommitment` |
| Fuzz: no panic | `FuzzDecryptNeverPanics` |
| Fuzz: round trip | `FuzzRoundTripWithContext` |
| Wycheproof | `TestWycheproofAESGCM`, `TestWycheproofChaCha20Poly1305` |
| Audit tamper | `TestTamperDetected` |
| Keyring selection | `TestKeyIDSelection`, `TestKeyIDMismatchFails` |
| Password verify | `TestHashAndVerify` |

If a test is removed or weakened, the corresponding claim in this document
should be revised.

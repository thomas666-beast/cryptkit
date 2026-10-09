// Package cipher provides AEAD-based encryption and decryption for byte
// slices, streams, and files.
//
// The package is algorithm-agnostic: AEADs live in a registry and can be
// replaced or extended. Defaults are safe (XChaCha20-Poly1305, 24-byte
// random nonce, key commitment on).
//
// Two layers sit on top of plain AEAD:
//
//   - The Context-Binding Layer (context.Context) binds a ciphertext to a
//     structured, mandatory descriptor. Decryption with the wrong context
//     fails, even with the right key.
//   - Key commitment binds the ciphertext to the key, so wrong-key attempts
//     fail before AEAD verification.
//
// For files and streams, plaintext is split into fixed-size chunks with
// per-chunk nonce derivation and chunk-index binding in AAD. Memory use is
// bounded regardless of input size.
package cipher

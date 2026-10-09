// Package envelope defines cryptkit's on-disk ciphertext format.
//
// A v1 envelope is a self-describing header followed by an optional key
// commitment and then AEAD ciphertext:
//
//	[ header ][ commitment? ][ ciphertext+tag ]
//
// The header is:
//
//	[ magic 8 ][ ver 1 ][ alg 1 ][ kdf 1 ][ flags 1 ][ kdfLen 4 ]
//	[ kdfParams N ][ nonce M ][ keyIDLen 2 ][ keyID K ]
//
// The keyID section is present only when flag bit 0x04 is set. Old readers
// ignore unknown flags, so files written without a key ID parse identically.
//
// All decryption paths should go through ParseView, which returns the
// three regions separately so callers never compute offsets by hand.
package envelope

// Package context implements cryptkit's Context-Binding Layer (CBL).
//
// A Context is a structured, canonical descriptor of "what this ciphertext
// is and who it belongs to". Purpose and Subject are mandatory; Origin,
// Epoch, and Extra are optional.
//
// The Context is canonicalized and included in the AEAD's associated data.
// At decryption the caller must supply the same Context; a mismatch fails
// even when the key is correct.
package context

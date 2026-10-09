// Package keys provides key material loading, generation, and a
// multi-key Keyring for rotation.
//
// Supported encodings: raw bytes, hex, base64, files, environment
// variables. Key IDs are SHA-256(key)[:8] by default and are non-secret
// identifiers used to select the right key without trial decryption.
package keys

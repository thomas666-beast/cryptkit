// Package audit implements a tamper-evident, append-only operation log.
//
// Each record is a JSON object with an HMAC-SHA256 signature under a log
// key, and a PrevHash field referencing the previous record's hash. Any
// modification to a past record breaks the chain and is detectable by
// Verify in a single O(n) pass.
//
// The log records only metadata — operation type, algorithm, context
// hash, key ID, byte count, timestamp — never plaintext or ciphertext.
package audit

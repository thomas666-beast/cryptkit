// Package password provides password hashing and verification.
//
// Argon2id is the primary scheme and uses the PHC string format:
//
//	$cryptkit$argon2id$v=19$m=65536,t=3,p=4$<b64salt>$<b64hash>
//
// Bcrypt verification is also supported for migration.
//
// NeedsRehash reports whether a stored hash was produced with weaker
// parameters than the current default.
package password

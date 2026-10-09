// Package passgen generates random passwords, passphrases, and PINs.
//
// All generators accept a Rand io.Reader, so callers can inject their
// own entropy source.
//
// Charset is composable and supports excluding ambiguous characters
// (0/O/1/l/I). BuiltinWordlist returns the EFF short wordlist.
package passgen

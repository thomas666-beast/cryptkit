package cipher

import (
	"os"
)

// FileOptions mirrors StreamOptions but for file paths.
type FileOptions struct {
	StreamOptions
	// Perm is the file mode for the output file. 0 => 0o600.
	Perm os.FileMode
	// Overwrite allows replacing an existing output file.
	Overwrite bool
}

func (o FileOptions) perm() os.FileMode {
	if o.Perm == 0 {
		return 0o600
	}
	return o.Perm
}

// EncryptFile encrypts src into dst using streamed chunks.
func EncryptFile(src, dst string, key []byte, opts FileOptions) error {
	if !opts.Overwrite {
		if _, err := os.Stat(dst); err == nil {
			return os.ErrExist
		}
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, opts.perm())
	if err != nil {
		return err
	}
	defer out.Close()

	return EncryptStream(out, in, key, opts.StreamOptions)
}

// DecryptFile decrypts src into dst.
func DecryptFile(src, dst string, key []byte, opts FileOptions) error {
	if !opts.Overwrite {
		if _, err := os.Stat(dst); err == nil {
			return os.ErrExist
		}
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, opts.perm())
	if err != nil {
		return err
	}
	defer out.Close()

	return DecryptStream(out, in, key, opts.StreamOptions)
}

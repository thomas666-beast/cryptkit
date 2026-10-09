package passgen

import (
	"crypto/rand"
	"errors"
	"io"
	"strings"
)

var (
	ErrEmptyAlphabet  = errors.New("cryptkit/passgen: empty alphabet")
	ErrLengthTooShort = errors.New("cryptkit/passgen: length too short for required classes")
)

// GenOptions controls random-password generation.
type GenOptions struct {
	Length          int
	Charset         Charset
	EnsureEachClass bool
	Rand            io.Reader
}

func (o GenOptions) rand() io.Reader {
	if o.Rand != nil {
		return o.Rand
	}
	return rand.Reader
}

// Generate returns a random password.
func Generate(opts GenOptions) (string, error) {
	if opts.Length <= 0 {
		opts.Length = 20
	}
	if opts.Charset == (Charset{}) {
		opts.Charset = DefaultCharset()
	}
	alphabet := opts.Charset.Alphabet()
	if alphabet == "" {
		return "", ErrEmptyAlphabet
	}
	classes := opts.Charset.Classes()
	if opts.EnsureEachClass && opts.Length < len(classes) {
		return "", ErrLengthTooShort
	}

	out := make([]byte, 0, opts.Length)
	if opts.EnsureEachClass {
		for _, cls := range classes {
			pool := dedupeExclude(cls, opts.Charset.Exclude)
			if pool == "" {
				continue
			}
			c, err := randChar(opts.rand(), pool)
			if err != nil {
				return "", err
			}
			out = append(out, c)
		}
	}
	for len(out) < opts.Length {
		c, err := randChar(opts.rand(), alphabet)
		if err != nil {
			return "", err
		}
		out = append(out, c)
	}
	if err := shuffle(opts.rand(), out); err != nil {
		return "", err
	}
	return string(out), nil
}

// GeneratePIN returns a numeric PIN.
func GeneratePIN(digits int, r io.Reader) (string, error) {
	if digits <= 0 {
		digits = 6
	}
	const pool = "0123456789"
	b := make([]byte, digits)
	for i := range b {
		c, err := randChar(r, pool)
		if err != nil {
			return "", err
		}
		b[i] = c
	}
	return string(b), nil
}

// GeneratePassphrase returns a passphrase by joining words.
// wordlist nil => BuiltinWordlist().
func GeneratePassphrase(words int, separator string, wordlist []string, r io.Reader) (string, error) {
	if words <= 0 {
		words = 5
	}
	if separator == "" {
		separator = "-"
	}
	if wordlist == nil {
		wordlist = BuiltinWordlist()
	}
	if len(wordlist) == 0 {
		return "", errors.New("cryptkit/passgen: empty wordlist")
	}
	if r == nil {
		r = rand.Reader
	}
	parts := make([]string, words)
	for i := range parts {
		idx, err := randIndex(r, len(wordlist))
		if err != nil {
			return "", err
		}
		parts[i] = wordlist[idx]
	}
	return strings.Join(parts, separator), nil
}

func randChar(r io.Reader, pool string) (byte, error) {
	idx, err := randIndex(r, len(pool))
	if err != nil {
		return 0, err
	}
	return pool[idx], nil
}

// randIndex returns uniform random in [0,n) using rejection sampling.
func randIndex(r io.Reader, n int) (int, error) {
	if n <= 0 {
		return 0, ErrEmptyAlphabet
	}
	const maxUint32 = ^uint32(0)
	limit := maxUint32 - (maxUint32 % uint32(n))
	var buf [4]byte
	for {
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return 0, err
		}
		v := uint32(buf[0])<<24 | uint32(buf[1])<<16 | uint32(buf[2])<<8 | uint32(buf[3])
		if v < limit {
			return int(v % uint32(n)), nil
		}
	}
}

func shuffle(r io.Reader, b []byte) error {
	for i := len(b) - 1; i > 0; i-- {
		j, err := randIndex(r, i+1)
		if err != nil {
			return err
		}
		b[i], b[j] = b[j], b[i]
	}
	return nil
}

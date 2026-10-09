package passgen

import "strings"

// Charset selects which character classes to include.
type Charset struct {
	Lower   bool
	Upper   bool
	Digits  bool
	Symbols bool
	// Custom is appended verbatim (after deduplication).
	Custom string
	// Exclude is removed from the final set (e.g. "0O1lI").
	Exclude string
}

const (
	lowerChars   = "abcdefghijklmnopqrstuvwxyz"
	upperChars   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digitChars   = "0123456789"
	symbolChars  = "!@#$%^&*()-_=+[]{};:,.<>?/|~"
	ambiguousSet = "0O1lI|`'\""
)

// Classes returns the list of enabled class strings.
func (c Charset) Classes() []string {
	var out []string
	if c.Lower {
		out = append(out, lowerChars)
	}
	if c.Upper {
		out = append(out, upperChars)
	}
	if c.Digits {
		out = append(out, digitChars)
	}
	if c.Symbols {
		out = append(out, symbolChars)
	}
	if c.Custom != "" {
		out = append(out, c.Custom)
	}
	return out
}

// Alphabet returns the full deduplicated character pool.
func (c Charset) Alphabet() string {
	var b strings.Builder
	for _, s := range c.Classes() {
		b.WriteString(s)
	}
	return dedupeExclude(b.String(), c.Exclude)
}

func dedupeExclude(s, exclude string) string {
	seen := map[rune]bool{}
	var b strings.Builder
	excl := map[rune]bool{}
	for _, r := range exclude {
		excl[r] = true
	}
	for _, r := range s {
		if excl[r] || seen[r] {
			continue
		}
		seen[r] = true
		b.WriteRune(r)
	}
	return b.String()
}

// DefaultCharset is a sane starting point.
func DefaultCharset() Charset {
	return Charset{Lower: true, Upper: true, Digits: true, Symbols: true}
}

// AmbiguousFree removes visually confusable characters.
func (c Charset) AmbiguousFree() Charset {
	c.Exclude += ambiguousSet
	return c
}

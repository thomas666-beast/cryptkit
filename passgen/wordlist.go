package passgen

import (
	_ "embed"
	"strings"
)

//go:embed eff_short.txt
var effShort string

var builtinWords []string

// BuiltinWordlist returns the EFF short wordlist (7,776 words).
func BuiltinWordlist() []string {
	if builtinWords == nil {
		builtinWords = strings.Fields(effShort)
	}
	return builtinWords
}

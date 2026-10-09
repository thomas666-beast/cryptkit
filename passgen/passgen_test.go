package passgen_test

import (
    "strings"
    "testing"

    "github.com/thomas666-beast/cryptkit/passgen"
)

func TestGenerateDefaults(t *testing.T) {
    pw, err := passgen.Generate(passgen.GenOptions{Length: 24, EnsureEachClass: true})
    if err != nil {
        t.Fatal(err)
    }
    if len(pw) != 24 {
        t.Fatalf("length = %d", len(pw))
    }
    var hasL, hasU, hasD, hasS bool
    for _, r := range pw {
        switch {
        case r >= 'a' && r <= 'z':
            hasL = true
        case r >= 'A' && r <= 'Z':
            hasU = true
        case r >= '0' && r <= '9':
            hasD = true
        default:
            hasS = true
        }
    }
    if !(hasL && hasU && hasD && hasS) {
        t.Fatalf("missing class: %q", pw)
    }
}

func TestGenerateUniqueness(t *testing.T) {
    seen := map[string]bool{}
    for i := 0; i < 100; i++ {
        pw, err := passgen.Generate(passgen.GenOptions{Length: 32})
        if err != nil {
            t.Fatal(err)
        }
        if seen[pw] {
            t.Fatal("duplicate password generated")
        }
        seen[pw] = true
    }
}

func TestPassphrase(t *testing.T) {
    pp, err := passgen.GeneratePassphrase(6, "-", nil, nil)
    if err != nil {
        t.Fatal(err)
    }
    if got := len(strings.Split(pp, "-")); got != 6 {
        t.Fatalf("word count = %d", got)
    }
}

func TestAmbiguousFree(t *testing.T) {
    cs := passgen.DefaultCharset().AmbiguousFree()
    pw, err := passgen.Generate(passgen.GenOptions{Length: 200, Charset: cs})
    if err != nil {
        t.Fatal(err)
    }
    for _, bad := range []string{"0", "O", "1", "l", "I"} {
        if strings.Contains(pw, bad) {
            t.Fatalf("found ambiguous char %q in %q", bad, pw)
        }
    }
}

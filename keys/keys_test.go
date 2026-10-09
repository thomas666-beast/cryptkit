package keys_test

import (
    "testing"

    "github.com/thomas666-beast/cryptkit/keys"
)

func TestGenerateAndRoundTrip(t *testing.T) {
    k, err := keys.Generate(32, nil)
    if err != nil {
        t.Fatal(err)
    }
    if len(k) != 32 {
        t.Fatalf("len = %d", len(k))
    }
    back, err := keys.FromHex(keys.ToHex(k))
    if err != nil || string(back) != string(k) {
        t.Fatalf("hex round trip: %v", err)
    }
    back, err = keys.FromBase64(keys.ToBase64(k))
    if err != nil || string(back) != string(k) {
        t.Fatalf("b64 round trip: %v", err)
    }
}

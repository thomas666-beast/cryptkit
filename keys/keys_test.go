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

func TestKeyringLifecycle(t *testing.T) {
	r := keys.NewKeyring()
	k1, _ := keys.Generate(32, nil)
	k2, _ := keys.Generate(32, nil)
	r.Add("a", k1, true)
	r.Add("b", k2, false)

	if r.Active() != "a" {
		t.Fatalf("active: %s", r.Active())
	}
	if err := r.SetActive("b"); err != nil {
		t.Fatal(err)
	}
	if r.Active() != "b" {
		t.Fatalf("active: %s", r.Active())
	}
	if len(r.Candidates()) != 2 {
		t.Fatalf("candidates: %d", len(r.Candidates()))
	}
	r.Remove("b")
	if r.Active() != "a" {
		t.Fatalf("after remove, active: %s", r.Active())
	}
	if got := r.Names(); len(got) != 1 || got[0] != "a" {
		t.Fatalf("names: %v", got)
	}
}

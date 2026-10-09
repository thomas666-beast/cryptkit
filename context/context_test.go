package context_test

import (
	"testing"

	"github.com/thomas666-beast/cryptkit/context"
)

func TestCanonicalStable(t *testing.T) {
	a := context.Context{
		Purpose: "backup", Subject: "user:42", Origin: "host:db-01", Epoch: 1730000000,
		Extra: map[string]string{"tenant": "acme", "app": "billing"},
	}
	b := context.Context{
		Purpose: "backup", Subject: "user:42", Origin: "host:db-01", Epoch: 1730000000,
		Extra: map[string]string{"app": "billing", "tenant": "acme"},
	}
	ca, _ := a.Canonical()
	cb, _ := b.Canonical()
	if string(ca) != string(cb) {
		t.Fatal("canonicalization depends on map order")
	}
}

func TestRequired(t *testing.T) {
	if _, err := (context.Context{}).Canonical(); err == nil {
		t.Fatal("expected error for missing purpose")
	}
	if _, err := (context.Context{Purpose: "x"}).Canonical(); err == nil {
		t.Fatal("expected error for missing subject")
	}
}

func TestEqual(t *testing.T) {
	a := context.Context{Purpose: "p", Subject: "s"}
	b := context.Context{Purpose: "p", Subject: "s"}
	ok, err := a.Equal(b)
	if err != nil || !ok {
		t.Fatal("expected equal")
	}
	c := context.Context{Purpose: "p", Subject: "other"}
	ok, _ = a.Equal(c)
	if ok {
		t.Fatal("expected not equal")
	}
}

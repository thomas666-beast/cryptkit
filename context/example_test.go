package context_test

import (
	"fmt"

	"github.com/thomas666-beast/cryptkit/context"
)

func ExampleContext_Canonical() {
	c := context.Context{
		Purpose: "backup",
		Subject: "user:42",
		Extra:   map[string]string{"tenant": "acme"},
	}
	can, _ := c.Canonical()
	fmt.Println(string(can[:8]))
	// Output: cryptkit
}

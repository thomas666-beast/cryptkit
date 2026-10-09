package passgen_test

import (
	"fmt"

	"github.com/thomas666-beast/cryptkit/passgen"
)

func ExampleGenerate() {
	pw, _ := passgen.Generate(passgen.GenOptions{Length: 20, EnsureEachClass: true})
	fmt.Println(len(pw))
	// Output: 20
}

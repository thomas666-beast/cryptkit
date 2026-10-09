package password_test

import (
	"fmt"

	"github.com/thomas666-beast/cryptkit/password"
)

func ExampleHashPassword() {
	hash, _ := password.HashPassword("hunter2")
	fmt.Println(password.VerifyPassword("hunter2", hash))
	fmt.Println(password.VerifyPassword("wrong", hash) != nil)
	// Output:
	// <nil>
	// true
}

// A small reflected program used to test recovery against garble. The Account
// struct is marshalled with encoding/json, so its type descriptor, field names,
// and json tags must survive obfuscation (reflect needs them) and garble emits
// an obfuscated->original name table that maps the hashed identifiers back. The
// os/exec reference is a stdlib capability anchor garble leaves in clear.
package main

import (
	"encoding/json"
	"fmt"
	"os/exec"
)

type Account struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Balance  int64  `json:"balance"`
}

func (a Account) Describe() string {
	return fmt.Sprintf("%s has %d", a.Username, a.Balance)
}

const apiKey = "SUPER_SECRET_API_KEY_abcdefghijklmnop"
const endpoint = "https://internal.example.com/v1/transfer"

func main() {
	a := Account{Username: "alice", Password: "hunter2", Balance: 100}
	b, err := json.Marshal(a)
	if err != nil {
		return
	}
	fmt.Println(string(b), a.Describe(), apiKey, endpoint)
	// Runtime-guarded so the compiler keeps os/exec.Command in the binary as a
	// capability anchor without ever running it.
	if len(b) == 0 {
		_ = exec.Command("never").Run()
	}
}

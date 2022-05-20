package main

import (
	"encoding/json"
	"fmt"

	"github.com/noandrea/rl2020"
)

func main() {

	revocationListID := "https://example.com/credentials/status/3"

	rl, err := rl2020.NewRevocationList(revocationListID, 16)
	if err != nil {
		panic(err)
	}
	// make some updatest to the revocation list
	rl.Revoke(10)
	rl.Revoke(100)
	rl.Revoke(1000)
	rl.Revoke(10000)

	var cs rl2020.CredentialStatus
	var revoked bool
	cs = rl2020.NewCredentialStatus(revocationListID, 10)

	revoked, _ = rl.IsRevoked(cs)
	fmt.Println(revoked)

	cs = rl2020.NewCredentialStatus(revocationListID, 101)

	revoked, _ = rl.IsRevoked(cs)
	fmt.Println(revoked)

	v, _ := json.Marshal(rl)
	fmt.Printf("%s\n", v)

	fmt.Printf("%b\n", rl.bitSet)

}

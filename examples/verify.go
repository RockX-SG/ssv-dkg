package main

import (
	"encoding/hex"
	"fmt"
	"github.com/herumi/bls-eth-go-binary/bls"
	"os"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {

	if len(os.Args) < 4 {
		fmt.Println("Usage: verify <pk> <msg> <sig>")
		os.Exit(1)
	}
	pkHex := os.Args[1]
	msgHex := os.Args[2]
	sigHex := os.Args[3]

	bls.Init(bls.BLS12_381)
	bls.SetETHmode(bls.EthModeDraft07)

	var (
		sig bls.Sign
		pk  bls.PublicKey
	)

	err := pk.DeserializeHexStr(pkHex)
	check(err)
	msg, err := hex.DecodeString(msgHex)
	check(err)
	err = sig.DeserializeHexStr(sigHex)
	check(err)

	v := sig.VerifyByte(&pk, msg)
	fmt.Printf("Valid: %v\n", v)
}

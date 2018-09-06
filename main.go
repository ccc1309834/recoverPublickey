package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"recover/secp256k1"
)

func main() {
	curve := secp256k1.S256()
	//generate priv
	priv, _ := ecdsa.GenerateKey(curve, rand.Reader)
	pubk := priv.Public().(*ecdsa.PublicKey)
	fmt.Println("pubX", pubk.X, "pubY", pubk.Y)

	//hash
	e := sha256.Sum256([]byte("helloworld"))

	//priv's length may be less than 32
	priv_byte := make([]byte, 32)
	copy(priv_byte[32-len(priv.D.Bytes()):], priv.D.Bytes())

	//sign
	sig, _ := secp256k1.Sign(e[:], priv_byte)

	//recover pub
	if pub, err := recover(e[:], sig, curve); err != nil {
		fmt.Println("Recover Fail", "err", err)
	} else {
		if ecdsa.Verify(pub, e[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:64])) {
			fmt.Println("Verify Success", "pubX", pub.X, "pubY", pub.Y)
		} else {
			fmt.Println("Verify Fail", "pubX", pub.X, "pubY", pub.Y)
		}
	}

}

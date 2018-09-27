package main

import (
	"crypto/rand"
	"crypto/sm2"
	"crypto/sm3"
	"fmt"
)

func main() {
	curve := sm2.P256_sm2()
	//generate priv
	priv, _ := sm2.GenerateKey(curve, rand.Reader)
	pubk := priv.Public().(*sm2.PublicKey)
	fmt.Println("====================priv's publickey====================")
	fmt.Println(pubk)
	fmt.Println()

	//hash
	e := sm3.Sum([]byte("helloworld"))

	//sign
	r, s, v, _ := Sign(rand.Reader, priv, e[:])
	fmt.Println("====================sm2 sig====================")
	fmt.Println("r:", r, "s:", s, "v:", v)
	fmt.Println()

	//recover pub
	if pub, err := recover(e[:], r, s, v, curve); err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("====================recover success,publickey====================")
		fmt.Println(pub)
		fmt.Println("Verify: Success")
	}
}

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
	fmt.Println("pubX", pubk.X, "pubY", pubk.Y)

	//hash
	e := sm3.Sum([]byte("helloworld"))

	//sign
	r, s, v, _ := Sign(rand.Reader, priv, e[:])
	
	//recover pub
	if pub, err := recover(e[:], r, s, v, curve); err != nil {
		fmt.Println("Recover Fail", "err", err)
	} else {
		if sm2.Verify(pub, e[:], r, s) {
			fmt.Println("Verify Success")
			fmt.Println("pubX", pub.X, "pubY", pub.Y)

		} else {
			fmt.Println("Verify Fail")
		}
	}
}

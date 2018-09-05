package main

import (
	"crypto/ecdsa"
	"errors"
	"math/big"
	"recover/secp256k1"
)

func recover(e, sig []byte, curve *secp256k1.BitCurve) (*ecdsa.PublicKey, error) {
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:64])
	v := new(big.Int).SetBytes(sig[64:])
	n := curve.Params().N

	//x to point
	x, y, err := x_to_point(r, v, curve)
	if err != nil {
		return nil, err
	}

	x_inverse := new(big.Int).ModInverse(x, n)
	//R*s
	x1, y1 := curve.ScalarMult(x, y, s.Bytes())

	//G*e
	x2, y2 := curve.ScalarBaseMult(e[:])
	//R*s-G*e
	x3, y3 := curve.Add(x1, y1, x2, y2.Neg(y2))
	//x^-1(R*s-G*e)
	pubx, puby := curve.ScalarMult(x3, y3, x_inverse.Bytes())

	//recover pub
	pub := &ecdsa.PublicKey{
		Curve: secp256k1.S256(),
		X:     pubx,
		Y:     puby,
	}

	//verify
	if ecdsa.Verify(pub, e[:], r, s) {
		return pub, nil
	}
	return nil, errors.New("recover fail, cannot found pubkey")
}

func x_to_point(r, v *big.Int, curve *secp256k1.BitCurve) (*big.Int, *big.Int, error) {
	p := curve.Params().P
	b := curve.Params().B
	n := curve.Params().N
	x := new(big.Int).Add(r, big.NewInt(0))

	//Euler criterion，y^((p+1)/4)=1 mod p
	p_add_1 := new(big.Int).Add(p, big.NewInt(1))
	p_add_1_div_4 := p_add_1.Div(p_add_1, big.NewInt(4))

	//c=x^3+b mod p
	c := new(big.Int).Exp(x, big.NewInt(3), p)
	c.Add(c, b)
	c.Mod(c, p)

	//R=(x,y)
	y := new(big.Int).Exp(c, p_add_1_div_4, p)
	if v.Cmp(big.NewInt(0)) == 0 && new(big.Int).Mod(y, big.NewInt(2)).Cmp(big.NewInt(0)) == 1 {
		y.Neg(y)
		y.Mod(y, p)
	} else if v.Cmp(big.NewInt(1)) == 0 && new(big.Int).Mod(y, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
		y.Neg(y)
		y.Mod(y, p)
	}

	//y^2==c，nR==O
	if new(big.Int).Exp(y, big.NewInt(2), p).Cmp(c) != 0 {
		return nil, nil, errors.New("recover fail, y^2!=c")
	}
	if a, b := curve.ScalarMult(x, y, n.Bytes()); a != nil && b != nil {
		return nil, nil, errors.New("recover fail, nR!=O")
	}

	return x, y, nil
}

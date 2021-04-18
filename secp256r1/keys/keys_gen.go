package keys

import (
	"Crypto/secp256r1/ecc_math"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
)

type KeyPair struct {
	privateKey big.Int
	PublicKey  ecc_math.ECPoint
}

func GetPrivateKey (pair KeyPair) big.Int {
	return pair.privateKey
}

func GenKeyPair() (pair KeyPair) {
	privateBytes, x, y, _ := elliptic.GenerateKey(ecc_math.Curve, rand.Reader)
	private := new(big.Int)
	private.SetBytes(privateBytes)
	public := ecc_math.ECPointGen(x, y)
	pair.privateKey = *private
	pair.PublicKey = public
	return
}

func KeyPairToString(pair KeyPair) string {
	return fmt.Sprintf("%X", &pair.privateKey) + " " + ecc_math.ECPointToString(pair.PublicKey)
}

func PrintKeyPair(pair KeyPair)  {
	fmt.Println("Private key:\t", fmt.Sprintf("%X", &pair.privateKey), "\nPublic key:")
	ecc_math.PrintECPoint(pair.PublicKey)
}
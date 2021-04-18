package random

import (
	"Crypto/secp256r1/ecc_math"
	"crypto/rand"
	"math/big"
)

func GenerateRandomBigInt() *big.Int {
	n, err := rand.Int(rand.Reader, ecc_math.Curve.Params().N)
	if err == nil {
		return n
	}
	return nil
}

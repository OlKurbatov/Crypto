package main

import (
	"Crypto/secp256k1/ecc_math"
	"Crypto/secp256k1/keys"
	"Crypto/secp256k1/signatures/ring_sha256"
	"Crypto/secp256k1/signatures/schnorr_musig_sha256"
	"Crypto/secp256k1/signatures/schnorr_single_sha256"
	"fmt"
	"math/big"
	"time"
)

func main() {
	ringSignatureTest()
	schnorrSignatureTest()
}

func schnorrSignatureTest() {
	keyArray := new([schnorr_musig_sha256.N]keys.KeyPair)
	t1 := time.Now()
	for i := 0; i < len(keyArray); i++ {
		keyArray[i] = keys.GenKeyPair()
	}
	t2 := time.Now()
	fmt.Println("Time for generating ", schnorr_musig_sha256.N, " keypairs: ", t2.Sub(t1))

	pubKeyArray := new([schnorr_musig_sha256.N]ecc_math.ECPoint)
	for i := 0; i < len(pubKeyArray); i++ {
		pubKeyArray[i] = keyArray[i].PublicKey
	}

	rPairlist := new([schnorr_musig_sha256.N]schnorr_musig_sha256.RSinglePair)
	for i := 0; i < len(rPairlist); i++ {
		rPairlist[i] = schnorr_musig_sha256.FormSingleRPair()
	}
	RList := new([schnorr_musig_sha256.N]ecc_math.ECPoint)
	for i := 0; i < len(RList); i++ {
		RList[i] = rPairlist[i].R
	}

	t1 = time.Now()
	commonParameters := schnorr_musig_sha256.CommonParametersGen(*pubKeyArray, *RList)
	t2 = time.Now()
	fmt.Println("Time for common parameters generating: ", t2.Sub(t1))
	singleSignatureList := new([schnorr_musig_sha256.N]big.Int)

	t1 = time.Now()
	for i := 0; i < len(singleSignatureList); i++ {
		singleSignatureList[i] = schnorr_musig_sha256.FormSignaturePart("message", rPairlist[i], commonParameters, keyArray[i].PublicKey, keys.GetPrivateKey(keyArray[i]))
	}

	aggregatedSignature := schnorr_musig_sha256.AggregareSignature(commonParameters, *singleSignatureList)

	t2 = time.Now()
	fmt.Println("Time for generating signature: ", t2.Sub(t1))

	t1 = time.Now()
	fmt.Println(schnorr_single_sha256.SchnorrSignatureVerify("message", commonParameters.AggregatedPublicKey, aggregatedSignature))
	t2 = time.Now()
	fmt.Println("Time for verification signature: ", t2.Sub(t1))
}

func ringSignatureTest() {
	t1 := time.Now()
	keyArray := new([ring_sha256.N]keys.KeyPair)
	for i := 0; i < len(keyArray); i++ {
		keyArray[i] = keys.GenKeyPair()
	}
	t2 := time.Now()
	fmt.Println("Time for generating ", ring_sha256.N, " keypairs: ", t2.Sub(t1))
	pubKeyArray := new([ring_sha256.N]ecc_math.ECPoint)
	for i := 0; i < len(pubKeyArray); i++ {
		pubKeyArray[i] = keyArray[i].PublicKey
	}
	t1 = time.Now()
	sign := ring_sha256.RingSignatureGen("message", *pubKeyArray, 3, keys.GetPrivateKey(keyArray[3]))
	t2 = time.Now()
	fmt.Println("Time for generating signature: ", t2.Sub(t1))
	t1 = time.Now()
	fmt.Println(ring_sha256.RingSignatureVerify("message", *pubKeyArray, sign))
	t2 = time.Now()
	fmt.Println("Time for verification signature: ", t2.Sub(t1))
}

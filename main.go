package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

// Generate RSA key pair
func generateKeyPair(keySize int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, nil, err
	}
	return privKey, &privKey.PublicKey, nil
}

// Create a blinded message
func createBlindedMessage(pubKey *rsa.PublicKey, message []byte, blindingFactor *big.Int) (*big.Int, error) {
	if blindingFactor.Cmp(pubKey.N) >= 0 {
		return nil, errors.New("blinding factor must be smaller than N")
	}
	blindedMessage := new(big.Int).Exp(pubKey.E, blindingFactor, pubKey.N)
	blindedMessage.Mul(blindedMessage, new(big.Int).SetBytes(message))
	blindedMessage.Mod(blindedMessage, pubKey.N)
	return blindedMessage, nil
}

// Generate a proof using the Fiat-Shamir heuristic
func generateFiatShamirProof(pubKey *rsa.PublicKey, message []byte, blindingFactor *big.Int) ([]byte, error) {
	// Generate random w
	w, err := rand.Int(rand.Reader, pubKey.N)
	if err != nil {
		return nil, err
	}

	// Compute commitment W = g^w mod N
	W := new(big.Int).Exp(pubKey.E, w, pubKey.N)

	// Compute the challenge c = H(W || message)
	h := sha256.New()
	h.Write(W.Bytes())
	h.Write(message)
	cBytes := h.Sum(nil)
	c := new(big.Int).SetBytes(cBytes)

	// Compute response z = w + c * blindingFactor mod N-1
	z := new(big.Int).Mul(c, blindingFactor)
	z.Add(z, w).Mod(z, pubKey.N)

	return z.Bytes(), nil
}

func verifyFiatShamirProof(pubKey *rsa.PublicKey, message, proof []byte) bool {
	// Compute W' = (g^z * y^(-c)) mod N
	z := new(big.Int).SetBytes(proof)
	c := sha256.Sum256(append(message, proof...))
	y := new(big.Int).SetBytes(message)
	yc := new(big.Int).Exp(pubKey.E, y, pubKey.N)
	yc.ModInverse(yc, pubKey.N)
	WPrime := new(big.Int).Exp(pubKey.E, z, pubKey.N)
	WPrime.Mul(WPrime, yc).Mod(WPrime, pubKey.N)

	// Check if H(W' || message) == c
	h := sha256.New()
	h.Write(WPrime.Bytes())
	h.Write(message)
	cPrime := h.Sum(nil)

	return string(c[:]) == string(cPrime)
}

func main() {
	// Generate RSA key pair for the bank
	keySize := 2048
	bankPrivKey, bankPubKey, err := generateKeyPair(keySize)
	if err != nil {
		panic(err)
	}

	// User's payment message (amount and recipient)
	message := []byte("100,recipient_id")

	// Generate random blinding factor
	blindingFactor, err := rand.Int(rand.Reader, bankPubKey.N)
	if err != nil {
		panic(err)
	}

	// Create a blinded payment message
	blindedMessage, err := createBlindedMessage(bankPubKey, message, blindingFactor)
		if err != nil {
		panic(err)
	}

	// Bank signs the blinded payment message
	blindedSignature, err := rsa.SignBlindedMessage(bankPrivKey, blindedMessage)
	if err != nil {
		panic(err)
	}

	// User unblinds the signature
	unblindedSignature := rsa.UnblindSignature(bankPubKey, blindedSignature, blindingFactor)

	// User generates a Fiat-Shamir proof
	proof, err := generateFiatShamirProof(bankPubKey, message, blindingFactor)
	if err != nil {
		panic(err)
	}

	// User sends the payment message, the unblinded signature, and the proof to the recipient
	recipientVerifiesSignature := rsa.VerifySignature(bankPubKey, message, unblindedSignature)
	recipientVerifiesProof := verifyFiatShamirProof(bankPubKey, message, proof)

	if recipientVerifiesSignature && recipientVerifiesProof {
		fmt.Println("Payment signature and proof verified")
	} else {
		fmt.Println("Payment signature or proof invalid")
	}
}


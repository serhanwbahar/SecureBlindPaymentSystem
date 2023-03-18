package main

import (
	"crypto/rand"
	"testing"
)

func TestPrivacyPayment(t *testing.T) {
	// Generate RSA key pair for the bank
	keySize := 2048
	bankPrivKey, bankPubKey, err := generateKeyPair(keySize)
	if err != nil {
		t.Fatal(err)
	}

	// User's payment message (amount and recipient)
	message := []byte("100,recipient_id")

	// Generate random blinding factor
	blindingFactor, err := rand.Int(rand.Reader, bankPubKey.N)
	if err != nil {
		t.Fatal(err)
	}

	// Create a blinded payment message
	blindedMessage, err := createBlindedMessage(bankPubKey, message, blindingFactor)
	if err != nil {
		t.Fatal(err)
	}

	// Bank signs the blinded payment message
	blindedSignature, err := rsa.SignBlindedMessage(bankPrivKey, blindedMessage)
	if err != nil {
		t.Fatal(err)
	}

	// User unblinds the signature
	unblindedSignature := rsa.UnblindSignature(bankPubKey, blindedSignature, blindingFactor)

	// User generates a Fiat-Shamir proof
	proof, err := generateFiatShamirProof(bankPubKey, message, blindingFactor)
	if err != nil {
		t.Fatal(err)
	}

	// User sends the payment message, the unblinded signature, and the proof to the recipient
	recipientVerifiesSignature := rsa.VerifySignature(bankPubKey, message, unblindedSignature)
	recipientVerifiesProof := verifyFiatShamirProof(bankPubKey, message, proof)

	if recipientVerifiesSignature && recipientVerifiesProof {
		t.Log("Payment signature and proof verified")
	} else {
		t.Error("Payment signature or proof invalid")
	}
}

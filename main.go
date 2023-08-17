package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

func SignPSS(plaintext string, privKey rsa.PrivateKey) string {
	// crypto/rand.Reader is a good source of entropy for blinding the RSA operation.
	rng := rand.Reader
	hashed := sha256.Sum256([]byte(plaintext))
	var opts rsa.PSSOptions
	signature, err := rsa.SignPSS(rng, &privKey, crypto.SHA256, hashed[:], &opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from signing: %s\n", err)
		return "Error from signing"
	}
	return base64.StdEncoding.EncodeToString(signature)
}

func VerifyPSS(signature string, plaintext string, pubkey rsa.PublicKey) string {
	sig, _ := base64.StdEncoding.DecodeString(signature)
	hashed := sha256.Sum256([]byte(plaintext))
	var opts rsa.PSSOptions
	err := rsa.VerifyPSS(&pubkey, crypto.SHA256, hashed[:], sig, &opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from verification: %s\n", err)
		return "Error from verification:"
	}
	return "Signature Verification Passed"
}

func main() {

	publicKeyRaw, err := os.ReadFile("public.key")
	if err != nil {
		fmt.Println("Failed to read in public key: " + err.Error())
	}
	pubKeyStripped := strings.ReplaceAll(string(publicKeyRaw), `\n`, "\n")
	fmt.Println(string(pubKeyStripped))

	// read in private and public keys
	privateKeyRaw, err := os.ReadFile("private.key")
	if err != nil {
		fmt.Println("Failed to read in private key: " + err.Error())
	}

	privKeyStripped := strings.ReplaceAll(string(privateKeyRaw), `\n`, "\n")
	fmt.Println("PUblic key as read in from file")
	fmt.Println(string(privKeyStripped))

	p, _ := pem.Decode([]byte(privKeyStripped[:]))
	if p == nil {
		fmt.Println("Failed to decode private key as pem block!")
		os.Exit(-1)
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(p.Bytes)
	if err != nil {
		fmt.Println("Failed to parse private key in as pem encoded pkcs1 rsa key. Error: " + err.Error())
		os.Exit(-1)
	}

	pubKey := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
	pubKeyPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKey})

	fmt.Println("PUblic key as derived from private key: ")
	fmt.Println(string(pubKeyPem))

	if pubKeyStripped != string(pubKeyPem) {
		fmt.Println("YIKES! public key read in from file and public key generated from private key dont match!")
	}

	// read in body
	body, err := os.ReadFile("content.body")
	if err != nil {
		fmt.Println("Failed to read in body content: " + err.Error())
	}

	// read in signature
	signature, err := os.ReadFile("content.sig")
	if err != nil {
		fmt.Println("Failed to read in content signature: " + err.Error())
	}

	signatureOfBody := SignPSS(string(body[:]), *privateKey)
	fmt.Println("BEN SAYS. Here is the calculated signature: ")
	fmt.Println(signatureOfBody)

	fmt.Println(VerifyPSS(string(signature), string(body), privateKey.PublicKey))

}

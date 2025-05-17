package router

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptoRand "crypto/rand"
	"encoding/base64"

	"log"
	"sync"

	"golang.org/x/crypto/curve25519"
)

// TODO: don't store in memory
var (
	signingKey      *ecdsa.PrivateKey
	privateKey      [32]byte
	publicKeyString *string
	recipientsMu    sync.Mutex
	recipients      = map[string]string{} // publicKeyBase64 -> name
	challengesMu    sync.Mutex
	challenges      = map[string][]byte{} // publicKeyBase64 -> token
	disclosuresMu   sync.Mutex
	disclosures     = map[string]map[string]map[string]string{} // publicKeyBase64 -> org -> disclosureID -> share
	threshold       = 3
)

func createKeys() {
	var err error
	signingKey, err = ecdsa.GenerateKey(elliptic.P256(), cryptoRand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	_, err = cryptoRand.Read(privateKey[:])
	if err != nil {
		log.Fatal(err)
	}

	publicKey, err := curve25519.X25519(privateKey[:], curve25519.Basepoint)
	if err != nil {
		log.Fatal(err)
	}
	base64EncodedPublicKey := base64.StdEncoding.EncodeToString(publicKey)
	publicKeyString = &base64EncodedPublicKey
}

package router

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptoRand "crypto/rand"

	"log"
	"sync"

	"github.com/berkmancenter/rendezvous-point/types"
)

// TODO: don't store in memory
var (
	signingKey    *ecdsa.PrivateKey
	recipientsMu  sync.RWMutex
	recipients    = map[string]string{} // publicKeyBase64 -> name
	challengesMu  sync.Mutex
	challenges    = map[string]map[string]types.Challenge{} // publicKeyBase64 -> nonce -> Challenge
	disclosuresMu sync.RWMutex
	disclosures   = map[string]map[string]map[string]string{} // publicKeyBase64 -> org -> disclosureID -> share
	threshold     = 3
)

func createKeys() {
	var err error
	signingKey, err = ecdsa.GenerateKey(elliptic.P256(), cryptoRand.Reader)
	if err != nil {
		log.Fatal(err)
	}
}

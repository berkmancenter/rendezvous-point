package router

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func challengeAuth(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		key := c.Param("key")
		encryptedToken := c.Request().Header.Get("Authorization")
		err := verifyChallenge(key, encryptedToken)
		if err != nil {
			return echo.NewHTTPError(http.StatusUnauthorized, err)
		}
		return next(c)
	}
}

func newChallenge() []byte {
	challenge := make([]byte, 32)
	cryptoRand.Read(challenge)
	return challenge
}

func verifyChallenge(publicKey string, encryptedToken string) error {
	challenge, ok := challenges[publicKey]
	if !ok {
		return fmt.Errorf("no challenge")
	}
	encryptedTokenBytes, err := base64.StdEncoding.DecodeString(encryptedToken)
	if err != nil {
		return fmt.Errorf("invalid base64")
	}
	// Try to decrypt the token
	peerKeyBytes, err := base64.RawURLEncoding.DecodeString(publicKey)
	if err != nil {
		return fmt.Errorf("invalid public key")
	}
	decrypted, err := aesGCMOpen(encryptedTokenBytes, peerKeyBytes)
	if err != nil || string(decrypted) != string(challenge) {
		return fmt.Errorf("challenge failed")
	}

	return nil
}

func aesGCMOpen(ciphertext []byte, peerPublicKeyBytes []byte) ([]byte, error) {
	if len(peerPublicKeyBytes) != 32 {
		return nil, fmt.Errorf("invalid X25519 public key length")
	}

	// Derive shared secret using X25519
	sharedSecret, err := curve25519.X25519(privateKey[:], peerPublicKeyBytes)

	if err != nil {
		return nil, fmt.Errorf("key agreement failed: %w", err)
	}

	// Derive symmetric key using HKDF with SHA-256
	hkdfReader := hkdf.New(sha256.New, sharedSecret, []byte{}, []byte{})
	key := make([]byte, 32)
	if _, err := hkdfReader.Read(key); err != nil {
		return nil, fmt.Errorf("hkdf read error: %w", err)
	}

	// Decrypt using AES-GCM
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher init error: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aes gcm init error: %w", err)
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ct := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}
	return plaintext, nil
}

func encryptedToken(challenge []byte, serverPrivateKey []byte, clientPublicKey []byte) (*string, error) {
	sharedSecret, err := curve25519.X25519(privateKey[:], clientPublicKey[:])
	if err != nil {
		return nil, err
	}

	hkdfReader := hkdf.New(sha256.New, sharedSecret, []byte{}, []byte{})
	symmetricKey := make([]byte, 32)
	_, err = hkdfReader.Read(symmetricKey)
	if err != nil {
		return nil, err
	}

	// Encrypt challenge with AES-GCM
	block, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, challenge, nil)
	encryptedToken := base64.StdEncoding.EncodeToString(ciphertext)

	return &encryptedToken, nil
}

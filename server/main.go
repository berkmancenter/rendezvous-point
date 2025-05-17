// main.go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/openrdap/rdap"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"log"
	"net/http"
	"sync"
	"time"
)

// TODO: don't store in memory
var (
	signingKey      *ecdsa.PrivateKey
	privateKey      [32]byte
	publicKeyString *string
	recipientsMu    sync.Mutex
	recipients      = map[string]string{} // publicKeyBase64 -> name
	challenges      = map[string][]byte{} // publicKeyBase64 -> token
	disclosuresMu   sync.Mutex
	disclosures     = map[string]map[string]map[string]string{} // publicKeyBase64 -> orgHash -> disclosureID -> share
	threshold       = 3
)

type Recipient struct {
	Name      string `json:"name"`
	PublicKey string `json:"publicKey"`
}

type DisclosureRequest struct {
	ID        string `json:"id"`
	Recipient string `json:"recipient"`
	Share     string `json:"share"`
}

type InboxChallengeRequest struct {
	PublicKey string `json:"publicKey"`
}

type InboxChallengeResponse struct {
	Token           string `json:"token"`
	ServerPublicKey string `json:"serverPublicKey"`
}

type InboxRequest struct {
	PublicKey      string `json:"publicKey"`
	EncryptedToken string `json:"encryptedToken"`
}

type InboxDeleteRequest struct {
	PublicKey      string `json:"publicKey"`
	ID             string `json:"id"`
	EncryptedToken string `json:"encryptedToken"`
}

type InboxResponse struct {
	ID    string `json:"id"`
	Share string `json:"share"`
}

func lookupOrgByIP(ip string) (*string, error) {
	client := &rdap.Client{}
	result, err := client.QueryIP(ip)
	if err != nil {
		return nil, err
	}

	if len(result.Entities) > 0 {
		realName := result.Entities[0].VCard.Name()
		return &realName, nil
	} else {
		return &result.Name, nil
	}
}

func orgHash(text string) string {
	hasher := sha256.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

func credential(c echo.Context) error {
	ip := c.RealIP()
	organization, err := lookupOrgByIP(ip)
	if err != nil {
		return c.String(http.StatusInternalServerError, "could not lookup IP organization")
	}

	claims := jwt.MapClaims{
		"org": organization,
		"exp": time.Now().Add(48 * time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	signedToken, err := token.SignedString(signingKey)
	if err != nil {
		return c.String(http.StatusInternalServerError, "could not sign token")
	}

	return c.JSON(http.StatusOK, map[string]string{
		"organization": *organization,
		"credential":   signedToken,
	})
}

func disclose(c echo.Context) error {
	var req DisclosureRequest
	if err := json.NewDecoder(c.Request().Body).Decode(&req); err != nil {
		return c.String(http.StatusBadRequest, "invalid body")
	}
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	org := claims["org"].(string)
	orgHash := orgHash(org)
	disclosuresMu.Lock()
	defer disclosuresMu.Unlock()
	if disclosures[req.Recipient] == nil {
		disclosures[req.Recipient] = make(map[string]map[string]string)
	}
	if disclosures[req.Recipient][orgHash] == nil {
		disclosures[req.Recipient][orgHash] = make(map[string]string)
	}
	disclosures[req.Recipient][orgHash][req.ID] = req.Share
	return c.String(http.StatusOK, "transmission successful")
}

func register(c echo.Context) error {
	var r Recipient
	if err := c.Bind(&r); err != nil {
		return c.String(http.StatusBadRequest, "invalid body")
	}
	recipientsMu.Lock()
	defer recipientsMu.Unlock()
	recipients[r.PublicKey] = r.Name
	return c.String(http.StatusOK, "ok")
}

func listRecipients(c echo.Context) error {
	recipientsMu.Lock()
	defer recipientsMu.Unlock()
	var result []Recipient
	for key, name := range recipients {
		result = append(result, Recipient{Name: name, PublicKey: key})
	}
	return c.JSON(http.StatusOK, result)
}

func inboxChallenge(c echo.Context) error {
	var req InboxChallengeRequest
	if err := c.Bind(&req); err != nil {
		return c.String(http.StatusBadRequest, "invalid body")
	}
	token := make([]byte, 32)
	// TODO:
	cryptoRand.Read(token)
	challenges[req.PublicKey] = token

	return c.JSON(http.StatusOK, InboxChallengeResponse{
		Token:           base64.StdEncoding.EncodeToString(token),
		ServerPublicKey: *publicKeyString,
	})
}

func inbox(c echo.Context) error {
	var req InboxRequest
	if err := c.Bind(&req); err != nil {
		return c.String(http.StatusBadRequest, "invalid body")
	}
	if err := verifyChallenge(c, req.PublicKey, req.EncryptedToken); err != nil {
		return err
	}
	entries := disclosures[req.PublicKey]
	var result []InboxResponse
	for _, values := range entries {
		if len(values) >= threshold {
			for id, share := range values {
				result = append(result, InboxResponse{
					ID:    id,
					Share: share,
				})
			}
		}
	}
	return c.JSON(http.StatusOK, result)
}

func verifyChallenge(c echo.Context, publicKey string, encryptedToken string) error {
	challenge, ok := challenges[publicKey]
	if !ok {
		return c.String(http.StatusUnauthorized, "no challenge")
	}
	encryptedTokenBytes, err := base64.StdEncoding.DecodeString(encryptedToken)
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid base64")
	}
	// Try to decrypt the token
	peerKeyBytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid public key")
	}
	decrypted, err := aesGCMOpen(encryptedTokenBytes, peerKeyBytes)
	if err != nil || string(decrypted) != string(challenge) {
		return c.String(http.StatusUnauthorized, "challenge failed")
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

func inboxDelete(c echo.Context) error {
	var req InboxDeleteRequest
	if err := c.Bind(&req); err != nil {
		return c.String(http.StatusBadRequest, "invalid body")
	}
	if err := verifyChallenge(c, req.PublicKey, req.EncryptedToken); err != nil {
		return err
	}
	disclosuresMu.Lock()
	defer disclosuresMu.Unlock()

	if orgs, ok := disclosures[req.PublicKey]; ok {
		for orgHash, idMap := range orgs {
			if _, exists := idMap[req.ID]; exists {
				delete(idMap, req.ID)
				if len(idMap) == 0 {
					delete(orgs, orgHash)
				}
			}
		}
		if len(orgs) == 0 {
			delete(disclosures, req.PublicKey)
		}
	}

	return c.String(http.StatusOK, "ok")
}

func main() {
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

	e := echo.New()
	e.HideBanner = true

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())

	e.GET("/", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]interface{}{"publicKey": publicKeyString})
	})

	e.GET("/credential", credential)
	e.POST("/disclose", disclose, middleware.BodyLimit("2K"), echojwt.WithConfig(echojwt.Config{
		SigningKey:    &signingKey.PublicKey,
		SigningMethod: "ES256",
	}))
	e.POST("/register", register)
	e.GET("/recipients", listRecipients)
	e.POST("/inbox/challenge", inboxChallenge)
	e.POST("/inbox", inbox)
	e.DELETE("/inbox", inboxDelete)

	e.Logger.Fatal(e.Start(fmt.Sprintf(":%d", 8080)))
}

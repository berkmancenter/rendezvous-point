package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func setupTestServer() *echo.Echo {
	e := echo.New()
	// Reset globals
	recipients = make(map[string]string)
	challenges = make(map[string][]byte)
	disclosures = make(map[string]map[string]map[string]string)

	signingKey, _ = ecdsa.GenerateKey(elliptic.P256(), cryptoRand.Reader)
	_, _ = cryptoRand.Read(privateKey[:])
	publicKey, _ := curve25519.X25519(privateKey[:], curve25519.Basepoint)
	base64EncodedPublicKey := base64.StdEncoding.EncodeToString(publicKey)
	publicKeyString = &base64EncodedPublicKey

	// Register routes
	e.GET("/credential", credential)
	e.POST("/register", register)
	e.GET("/recipients", listRecipients)
	e.POST("/disclose", disclose, echo.WrapMiddleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Sign fake token
			token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
				"org": "TestOrg",
				"exp": time.Now().Add(time.Hour).Unix(),
				"iat": time.Now().Unix(),
			})
			signed, _ := token.SignedString(signingKey)
			r.Header.Set("Authorization", "Bearer "+signed)
			next.ServeHTTP(w, r)
		})
	}))
	e.POST("/inbox/challenge", inboxChallenge)
	e.POST("/inbox", inbox)
	e.DELETE("/inbox", inboxDelete)
	return e
}

func TestRegisterAndListRecipients(t *testing.T) {
	e := setupTestServer()
	rec := httptest.NewRecorder()

	body := `{"name":"Alice","publicKey":"testkey"}`
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	e.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/recipients", nil)
	e.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Alice")
}

func TestCredentialIssue(t *testing.T) {
	e := setupTestServer()

	req := httptest.NewRequest(http.MethodGet, "/credential", nil)
	req.RemoteAddr = "8.8.8.8:1234" // triggers RDAP call
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]string
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Contains(t, resp["organization"], "Google")
	assert.NotEmpty(t, resp["credential"])
}

func TestInboxChallengeAndAccessFlow(t *testing.T) {
	e := setupTestServer()

	pubKey := *publicKeyString
	reqBody := map[string]string{"publicKey": pubKey}
	buf, _ := json.Marshal(reqBody)

	// Step 1: Request a challenge
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/inbox/challenge", bytes.NewBuffer(buf))
	req.Header.Set("Content-Type", "application/json")
	e.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp InboxChallengeResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	tokenBytes, _ := base64.StdEncoding.DecodeString(resp.Token)

	// Step 2: Simulate disclosure submissions from 3 orgs
	orgs := []string{"OrgA", "OrgB", "OrgC"}
	for _, org := range orgs {
		orgHashVal := orgHash(org)
		if disclosures[pubKey] == nil {
			disclosures[pubKey] = make(map[string]map[string]string)
		}
		if disclosures[pubKey][orgHashVal] == nil {
			disclosures[pubKey][orgHashVal] = make(map[string]string)
		}
		for i := 0; i < 3; i++ {
			id := fmt.Sprintf("id-%s-%d", org, i)
			share := fmt.Sprintf("share-%s-%d", org, i)
			disclosures[pubKey][orgHashVal][id] = share
		}
	}

	// Step 3: Encrypt token with shared key
	peerPubKey, _ := base64.StdEncoding.DecodeString(pubKey)
	sharedSecret, _ := curve25519.X25519(privateKey[:], peerPubKey)

	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, nil)
	key := make([]byte, 32)
	hkdfReader.Read(key)

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	cryptoRand.Read(nonce)
	ct := gcm.Seal(nonce, nonce, tokenBytes, nil)
	encryptedToken := base64.StdEncoding.EncodeToString(ct)

	// Step 4: Access inbox
	inboxReq := InboxRequest{
		PublicKey:      pubKey,
		EncryptedToken: encryptedToken,
	}
	inboxBuf, _ := json.Marshal(inboxReq)

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/inbox", bytes.NewBuffer(inboxBuf))
	req.Header.Set("Content-Type", "application/json")
	e.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	var inboxResult []InboxResponse
	json.Unmarshal(rec.Body.Bytes(), &inboxResult)
	assert.Equal(t, 9, len(inboxResult))
}

func TestInboxDelete(t *testing.T) {
	e := setupTestServer()
	pubKey := *publicKeyString
	token := []byte("test-challenge")
	challenges[pubKey] = token

	// Create share
	org := "TestOrg"
	orgHashVal := orgHash(org)
	disclosures[pubKey] = map[string]map[string]string{
		orgHashVal: {"share-id": "share-value"},
	}

	// Encrypt challenge token
	peerPubKey, _ := base64.StdEncoding.DecodeString(pubKey)
	sharedSecret, _ := curve25519.X25519(privateKey[:], peerPubKey)

	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, nil)
	key := make([]byte, 32)
	hkdfReader.Read(key)

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	cryptoRand.Read(nonce)
	ct := gcm.Seal(nonce, nonce, token, nil)

	// Build delete request
	deleteReq := InboxDeleteRequest{
		PublicKey:      pubKey,
		ID:             "share-id",
		EncryptedToken: base64.StdEncoding.EncodeToString(ct),
	}
	body, _ := json.Marshal(deleteReq)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/inbox", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	e.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Verify deletion
	_, exists := disclosures[pubKey]
	assert.False(t, exists)
}

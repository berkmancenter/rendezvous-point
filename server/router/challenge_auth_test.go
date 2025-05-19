package router

import (
	cryptoRand "crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/berkmancenter/rendezvous-point/types"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/curve25519"
)

func TestVerifyChallenge_Success(t *testing.T) {
	var peerPrivateKey [32]byte
	cryptoRand.Read(peerPrivateKey[:])

	peerPublicKey, err := curve25519.X25519(peerPrivateKey[:], curve25519.Basepoint)
	assert.NoError(t, err)
	peerPublicKeyString := base64.RawURLEncoding.EncodeToString(peerPublicKey)

	challenge, err := newChallenge()
	assert.NoError(t, err)

	encodedNonce := base64.StdEncoding.Strict().EncodeToString(challenge.Nonce)

	challenges[peerPublicKeyString] = map[string]types.Challenge{encodedNonce: *challenge}

	encryptedToken, err := encryptedToken(challenge.Token, peerPrivateKey[:], challenge.EphemeralPublicKey[:])
	assert.NoError(t, err)

	// Test verification
	err = verifyChallenge(peerPublicKeyString, *encryptedToken, encodedNonce)
	assert.NoError(t, err)
}

func TestVerifyChallenge_NoChallenge(t *testing.T) {
	err := verifyChallenge("somekey", "!!!!", "nonce")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no challenge")
}

func TestVerifyChallenge_WrongNonce(t *testing.T) {
	var peerPrivateKey [32]byte
	cryptoRand.Read(peerPrivateKey[:])

	peerPublicKey, _ := curve25519.X25519(peerPrivateKey[:], curve25519.Basepoint)
	peerPublicKeyString := base64.RawURLEncoding.EncodeToString(peerPublicKey)

	challenge, _ := newChallenge()
	encodedNonce := base64.StdEncoding.Strict().EncodeToString(challenge.Nonce)

	// Store challenge under one nonce
	challengesMu.Lock()
	challenges[peerPublicKeyString] = map[string]types.Challenge{encodedNonce: *challenge}
	challengesMu.Unlock()

	// Use a different nonce
	err := verifyChallenge(peerPublicKeyString, "!!!", "invalid-nonce")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no challenge for nonce")
}

func TestVerifyChallenge_BadToken(t *testing.T) {
	var peerPrivateKey [32]byte
	cryptoRand.Read(peerPrivateKey[:])

	peerPublicKey, _ := curve25519.X25519(peerPrivateKey[:], curve25519.Basepoint)
	peerPublicKeyString := base64.RawURLEncoding.EncodeToString(peerPublicKey)

	challenge, _ := newChallenge()
	encodedNonce := base64.StdEncoding.Strict().EncodeToString(challenge.Nonce)

	challengesMu.Lock()
	challenges[peerPublicKeyString] = map[string]types.Challenge{encodedNonce: *challenge}
	challengesMu.Unlock()

	// Tampered token
	err := verifyChallenge(peerPublicKeyString, "badtoken==", encodedNonce)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid base64")
}

func TestChallengeAuth_Success(t *testing.T) {
	var peerPrivateKey [32]byte
	cryptoRand.Read(peerPrivateKey[:])
	peerPublicKey, _ := curve25519.X25519(peerPrivateKey[:], curve25519.Basepoint)
	peerPublicKeyString := base64.RawURLEncoding.EncodeToString(peerPublicKey)

	challenge, _ := newChallenge()
	encodedNonce := base64.StdEncoding.Strict().EncodeToString(challenge.Nonce)

	token, _ := encryptedToken(challenge.Token, peerPrivateKey[:], challenge.EphemeralPublicKey[:])

	// JSON encode token+nonce
	jsonPayload := fmt.Sprintf(`{"nonce":"%s","encryptedToken":"%s"}`, encodedNonce, *token)
	authHeader := "Bearer " + base64.StdEncoding.EncodeToString([]byte(jsonPayload))

	challengesMu.Lock()
	challenges[peerPublicKeyString] = map[string]types.Challenge{encodedNonce: *challenge}
	challengesMu.Unlock()

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/inbox/"+peerPublicKeyString, nil)
	req.Header.Set("Authorization", authHeader)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("key")
	c.SetParamValues(peerPublicKeyString)

	h := challengeAuth(func(c echo.Context) error {
		return c.String(http.StatusOK, "pass")
	})

	err := h(c)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "pass", rec.Body.String())
}

func TestChallengeAuth_MalformedBase64(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/inbox/somekey", nil)
	req.Header.Set("Authorization", "Bearer !!!not-base64")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("key")
	c.SetParamValues("somekey")

	err := challengeAuth(func(c echo.Context) error {
		return c.String(http.StatusOK, "pass")
	})(c)

	httpErr, ok := err.(*echo.HTTPError)
	assert.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
	assert.Contains(t, httpErr.Message.(string), "invalid base64")
}

func TestChallengeAuth_MalformedJSON(t *testing.T) {
	badJSON := base64.StdEncoding.EncodeToString([]byte("{not json}"))

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/inbox/somekey", nil)
	req.Header.Set("Authorization", "Bearer "+badJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("key")
	c.SetParamValues("somekey")

	err := challengeAuth(func(c echo.Context) error {
		return c.String(http.StatusOK, "pass")
	})(c)

	httpErr, ok := err.(*echo.HTTPError)
	assert.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
	assert.Contains(t, httpErr.Message.(string), "invalid json")
}

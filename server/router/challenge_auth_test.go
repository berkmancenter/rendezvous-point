package router

import (
	cryptoRand "crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

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

	challenges[peerPublicKeyString] = *challenge

	encryptedToken, err := encryptedToken(challenge.Token, peerPrivateKey[:], challenge.EphemeralPublicKey[:])
	assert.NoError(t, err)

	// Test verification
	err = verifyChallenge(peerPublicKeyString, *encryptedToken)
	assert.NoError(t, err)
}

func TestVerifyChallenge_NoChallenge(t *testing.T) {
	err := verifyChallenge("somekey", "!!!!")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no challenge")
}

func TestChallengeAuth_Unauthorized(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/inbox/somekey", nil)
	req.Header.Set("Authorization", "invalid")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("key")
	c.SetParamValues("somekey")

	h := challengeAuth(func(c echo.Context) error {
		return c.String(http.StatusOK, "pass")
	})

	err := h(c)
	httpErr, ok := err.(*echo.HTTPError)
	assert.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
	assert.Contains(t, httpErr.Message.(error).Error(), "no challenge")
}

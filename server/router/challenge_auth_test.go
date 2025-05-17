package router

import (
	cryptoRand "crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestVerifyChallenge_Success(t *testing.T) {
	createKeys()

	var peerPubliceKey [32]byte
	cryptoRand.Read(peerPubliceKey[:])

	challenge := newChallenge()

	peerPublicKeyStr := base64.RawURLEncoding.EncodeToString(peerPubliceKey[:])
	challenges[peerPublicKeyStr] = challenge

	encryptedToken, err := encryptedToken(challenge, privateKey[:], peerPubliceKey[:])
	assert.NoError(t, err)

	// Test verification
	err = verifyChallenge(peerPublicKeyStr, *encryptedToken)
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

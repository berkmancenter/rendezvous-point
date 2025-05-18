package router

import (
	"bytes"
	cryptoRand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/berkmancenter/rendezvous-point/types"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/curve25519"
)

func setupTestRouter() *echo.Echo {
	createKeys()
	e := echo.New()
	RegisterRoutes(e)
	return e
}

func TestRegisterAndListRecipients(t *testing.T) {
	e := setupTestRouter()
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
	assert.Contains(t, rec.Body.String(), "["+body+"]")
}

func TestCredentialIssue(t *testing.T) {
	e := setupTestRouter()

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
	e := setupTestRouter()

	var peerPrivateKey [32]byte
	cryptoRand.Read(peerPrivateKey[:])

	peerPublicKey, err := curve25519.X25519(peerPrivateKey[:], curve25519.Basepoint)
	assert.NoError(t, err)
	peerPublicKeyString := base64.RawURLEncoding.EncodeToString(peerPublicKey)

	// Step 1: Request a challenge
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/inbox/"+peerPublicKeyString+"/challenge", nil)

	e.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp types.InboxChallengeResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	token, err := base64.StdEncoding.DecodeString(resp.Token)
	assert.NoError(t, err)
	serverPublicKey, err := base64.StdEncoding.DecodeString(resp.ServerPublicKey)
	assert.NoError(t, err)

	// Step 2: Simulate disclosure submissions from 3 orgs
	orgs := []string{"OrgA", "OrgB", "OrgC"}
	for _, org := range orgs {
		if disclosures[string(peerPublicKey[:])] == nil {
			disclosures[string(peerPublicKey[:])] = make(map[string]map[string]string)
		}
		if disclosures[string(peerPublicKey[:])][org] == nil {
			disclosures[string(peerPublicKey[:])][org] = make(map[string]string)
		}
		for i := 0; i < 3; i++ {
			id := fmt.Sprintf("id-%s-%d", org, i)
			share := fmt.Sprintf("share-%s-%d", org, i)
			disclosures[string(peerPublicKey[:])][org][id] = share
		}
	}

	// Step 3: Encrypt token with shared key
	encryptedToken, err := encryptedToken(token, peerPrivateKey[:], serverPublicKey[:])
	assert.NoError(t, err)

	// Step 4: Access inbox
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/inbox/"+peerPublicKeyString, nil)
	req.Header.Set("Authorization", *encryptedToken)
	e.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	var inboxResult []types.InboxResponse
	json.Unmarshal(rec.Body.Bytes(), &inboxResult)
	assert.Equal(t, 9, len(inboxResult))
}

func TestInboxDelete(t *testing.T) {
	e := setupTestRouter()

	var peerPrivateKey [32]byte
	cryptoRand.Read(peerPrivateKey[:])

	peerPublicKey, err := curve25519.X25519(peerPrivateKey[:], curve25519.Basepoint)
	assert.NoError(t, err)
	peerPublicKeyString := base64.RawURLEncoding.EncodeToString(peerPublicKey)

	shareID := "share-id"

	// Step 1: Request a challenge
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/inbox/"+peerPublicKeyString+"/challenge", nil)

	e.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp types.InboxChallengeResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	token, err := base64.StdEncoding.DecodeString(resp.Token)
	assert.NoError(t, err)
	serverPublicKey, err := base64.StdEncoding.DecodeString(resp.ServerPublicKey)
	assert.NoError(t, err)

	// Step 2: Simulate a share
	org := "TestOrg"
	disclosures[string(peerPublicKey[:])] = map[string]map[string]string{
		org: {shareID: "share-value"},
	}

	// Step 3: Encrypt token with shared key
	privateKey := make([]byte, 32)
	cryptoRand.Read(privateKey)
	encryptedToken, err := encryptedToken(token, peerPrivateKey[:], serverPublicKey[:])
	assert.NoError(t, err)

	// Build delete request
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/inbox/"+peerPublicKeyString+"/"+shareID, nil)
	req.Header.Set("Authorization", *encryptedToken)
	e.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Verify deletion
	_, exists := disclosures[string(peerPublicKey[:])]
	assert.False(t, exists)
}

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
)

func setupTestRouter() *echo.Echo {
	createKeys()
	e := echo.New()
	RegisterRoutes(e)
	return e
}

// func TestRegisterAndGetRecipients(t *testing.T) {
// 	e := setupTestRouter()

// 	recipient := types.Recipient{
// 		Name:      "Alice",
// 		PublicKey: base64.StdEncoding.EncodeToString([]byte("test-key")),
// 	}
// 	body, _ := json.Marshal(recipient)
// 	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
// 	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
// 	rec := httptest.NewRecorder()
// 	c := e.NewContext(req, rec)

// 	err := postRegister(c)
// 	assert.NoError(t, err)
// 	assert.Equal(t, http.StatusOK, rec.Code)
// 	assert.Equal(t, "ok", rec.Body.String())

// 	// Get recipients
// 	req = httptest.NewRequest(http.MethodGet, "/recipients", nil)
// 	rec = httptest.NewRecorder()
// 	c = e.NewContext(req, rec)
// 	err = getRecipients(c)
// 	assert.NoError(t, err)
// 	assert.Equal(t, http.StatusOK, rec.Code)
// 	assert.Contains(t, rec.Body.String(), "Alice")
// }

// func TestInboxChallenge(t *testing.T) {
// 	e := setupTestRouter()

// 	key := base64.RawURLEncoding.EncodeToString([]byte("recipient-key"))
// 	req := httptest.NewRequest(http.MethodGet, "/inbox/"+key+"/challenge", nil)
// 	rec := httptest.NewRecorder()
// 	c := e.NewContext(req, rec)
// 	c.SetParamNames("key")
// 	c.SetParamValues(key)

// 	err := getInboxChallenge(c)
// 	assert.NoError(t, err)
// 	assert.Equal(t, http.StatusOK, rec.Code)
// 	assert.Contains(t, rec.Body.String(), "token")
// }

// func TestDeleteInboxId_InvalidKey(t *testing.T) {
// 	e := setupTestRouter()

// 	req := httptest.NewRequest(http.MethodDelete, "/inbox/invalid-base64/id123", nil)
// 	rec := httptest.NewRecorder()
// 	c := e.NewContext(req, rec)
// 	c.SetParamNames("key", "id")
// 	c.SetParamValues("invalid-base64", "id123")

// 	err := deleteInboxId(c)
// 	assert.NoError(t, err)
// 	assert.Equal(t, http.StatusBadRequest, rec.Code)
// 	assert.Contains(t, rec.Body.String(), "invalid key encoding")
// }

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

	var peerPublicKey [32]byte
	cryptoRand.Read(peerPublicKey[:])
	peerPublicKeyString := base64.RawURLEncoding.EncodeToString(peerPublicKey[:])

	// Step 1: Request a challenge
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/inbox/"+peerPublicKeyString+"/challenge", nil)

	e.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp types.InboxChallengeResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	challenge, _ := base64.StdEncoding.DecodeString(resp.Token)

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
	encryptedToken, err := encryptedToken(challenge, privateKey[:], peerPublicKey[:])
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

	var peerPublicKey [32]byte
	cryptoRand.Read(peerPublicKey[:])
	peerPublicKeyString := base64.RawURLEncoding.EncodeToString(peerPublicKey[:])

	shareID := "share-id"
	challenge := []byte("test-challenge")
	challenges[peerPublicKeyString] = challenge

	// Create share
	org := "TestOrg"
	disclosures[string(peerPublicKey[:])] = map[string]map[string]string{
		org: {shareID: "share-value"},
	}

	// Encrypt challenge token
	encryptedToken, err := encryptedToken(challenge, privateKey[:], peerPublicKey[:])
	assert.NoError(t, err)

	// Build delete request
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/inbox/"+peerPublicKeyString+"/"+shareID, nil)
	req.Header.Set("Authorization", *encryptedToken)
	e.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Verify deletion
	_, exists := disclosures[string(peerPublicKey[:])]
	assert.False(t, exists)
}

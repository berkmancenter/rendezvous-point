package router

import (
	"encoding/base64"
	"encoding/json"

	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"net/http"

	"github.com/berkmancenter/rendezvous-point/types"
)

func RegisterRoutes(e *echo.Echo) {
	createKeys()

	e.GET("/credential", getCredential)
	e.POST("/disclose", postDisclose, middleware.BodyLimit("2K"), echojwt.WithConfig(echojwt.Config{
		SigningKey:    &signingKey.PublicKey,
		SigningMethod: "ES256",
	}))
	e.POST("/register", postRegister)
	e.GET("/recipients", getRecipients)
	e.GET("/inbox/:key/challenge", getInboxChallenge)
	e.GET("/inbox/:key", getInbox, challengeAuth)
	e.DELETE("/inbox/:key/:id", deleteInboxId, challengeAuth)
}

func getCredential(c echo.Context) error {
	credential, err := newCredential(c)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, credential)
}

func postDisclose(c echo.Context) error {
	var req types.DisclosureRequest
	if err := json.NewDecoder(c.Request().Body).Decode(&req); err != nil {
		return c.String(http.StatusBadRequest, "invalid body")
	}

	key, err := base64.StdEncoding.DecodeString(req.Recipient)
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid key encoding")
	}

	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	org := claims["org"].(string)

	disclosuresMu.Lock()
	defer disclosuresMu.Unlock()
	if disclosures[string(key)] == nil {
		disclosures[string(key)] = make(map[string]map[string]types.VerifiableShare)
	}
	if disclosures[string(key)][org] == nil {
		disclosures[string(key)][org] = make(map[string]types.VerifiableShare)
	}
	disclosures[string(key)][org][req.ID] = req.VerifiableShare
	return c.String(http.StatusOK, "transmission successful")
}

func postRegister(c echo.Context) error {
	var r types.Recipient
	if err := c.Bind(&r); err != nil {
		return c.String(http.StatusBadRequest, "invalid body")
	}
	recipientsMu.Lock()
	defer recipientsMu.Unlock()
	recipients[r.PublicKey] = r.Name
	return c.String(http.StatusOK, "ok")
}

func getRecipients(c echo.Context) error {
	recipientsMu.RLock()
	defer recipientsMu.RUnlock()
	var result []types.Recipient
	for key, name := range recipients {
		result = append(result, types.Recipient{Name: name, PublicKey: key})
	}
	return c.JSON(http.StatusOK, result)
}

func getInboxChallenge(c echo.Context) error {
	key := c.Param("key")
	challenge, err := newChallenge()
	if err != nil {
		return c.String(http.StatusInternalServerError, "failed to generate challenge")
	}

	encodedNonce := base64.StdEncoding.EncodeToString(challenge.Nonce)

	challengesMu.Lock()
	defer challengesMu.Unlock()
	if challenges[key] == nil {
		challenges[key] = make(map[string]types.Challenge)
	}
	challenges[key][encodedNonce] = *challenge

	return c.JSON(http.StatusOK, types.InboxChallengeResponse{
		Token:     base64.StdEncoding.EncodeToString(challenge.Token),
		PublicKey: base64.StdEncoding.EncodeToString(challenge.EphemeralPublicKey),
		Nonce:     encodedNonce,
	})
}

func getInbox(c echo.Context) error {
	urlEncodedKey := c.Param("key")
	key, err := base64.RawURLEncoding.DecodeString(urlEncodedKey)
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid key encoding")
	}

	disclosuresMu.RLock()
	defer disclosuresMu.RUnlock()

	entries := disclosures[string(key)]
	var result []types.InboxResponse
	for org, values := range entries {
		if len(values) >= threshold {
			for id, share := range values {
				result = append(result, types.InboxResponse{
					ID:              id,
					Org:             org,
					VerifiableShare: share,
				})
			}
		}
	}
	return c.JSON(http.StatusOK, result)
}

func deleteInboxId(c echo.Context) error {
	urlEncodedKey := c.Param("key")
	key, err := base64.RawURLEncoding.DecodeString(urlEncodedKey)
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid key encoding")
	}
	id := c.Param("id")

	disclosuresMu.Lock()
	defer disclosuresMu.Unlock()

	if orgs, ok := disclosures[string(key)]; ok {
		for org, idMap := range orgs {
			if _, exists := idMap[id]; exists {
				delete(idMap, id)
				if len(idMap) == 0 {
					delete(orgs, org)
				}
			}
		}
		if len(orgs) == 0 {
			delete(disclosures, string(key))
		}
	}

	return c.String(http.StatusOK, "ok")
}

package router

import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/openrdap/rdap"
)

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

func newCredential(c echo.Context) (map[string]string, error) {
	ip := c.RealIP()
	organization, err := lookupOrgByIP(ip)
	if err != nil {
		return nil, c.String(http.StatusInternalServerError, "could not lookup IP organization")
	}

	claims := jwt.MapClaims{
		"org": organization,
		"exp": time.Now().Add(48 * time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	signedToken, err := token.SignedString(signingKey)
	if err != nil {
		return nil, c.String(http.StatusInternalServerError, "could not sign token")
	}

	return map[string]string{
		"organization": *organization,
		"credential":   signedToken,
	}, nil
}

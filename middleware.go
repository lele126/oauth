package oauth

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gogf/gf/frame/g"
	"github.com/gogf/gf/net/ghttp"
)

// BearerAuthentication middleware for Gin-Gonic
type BearerAuthentication struct {
	secretKey string
	provider  *TokenProvider
}

// NewBearerAuthentication create a BearerAuthentication middleware
func NewBearerAuthentication(secretKey string, formatter TokenSecureFormatter) *BearerAuthentication {
	ba := &BearerAuthentication{secretKey: secretKey}
	if formatter == nil {
		formatter = NewSHA256RC4TokenSecurityProvider([]byte(secretKey))
	}
	ba.provider = NewTokenProvider(formatter)
	return ba
}

// Authorize is the OAuth 2.0 middleware for Gin-Gonic resource server.
// Authorize creates a BearerAuthentication middlever and return the Authorize method.
func Authorize(secretKey string, formatter TokenSecureFormatter) ghttp.HandlerFunc {
	return NewBearerAuthentication(secretKey, nil).Authorize
}

// Authorize verifies the bearer token authorizing or not the request.
// Token is retreived from the Authorization HTTP header that respects the format
// Authorization: Bearer {access_token}
func (ba *BearerAuthentication) Authorize(r *ghttp.Request) {
	auth := r.Request.Header.Get("Authorization")
	token, err := ba.checkAuthorizationHeader(auth)
	if err != nil {
		r.Response.WriteJson(
			g.Map{
				"code": http.StatusUnauthorized,
				"msg":  "Not authorized: " + err.Error(),
			})
		r.ExitAll()
	} else {
		r.SetParam("oauth.credential", token.Credential)
		r.SetParam("oauth.claims", token.Claims)
		r.SetParam("oauth.scope", token.Scope)
		r.SetParam("oauth.tokentype", token.TokenType)
		r.SetParam("oauth.accesstoken", auth[7:])
		r.Middleware.Next()
	}
}

// Check header and token.
func (ba *BearerAuthentication) checkAuthorizationHeader(auth string) (t *Token, err error) {
	if len(auth) < 7 {
		return nil, errors.New("Invalid bearer authorization header")
	}
	authType := strings.ToLower(auth[:6])
	if authType != "bearer" {
		return nil, errors.New("Invalid bearer authorization header")
	}
	token, err := ba.provider.DecryptToken(auth[7:])
	if err != nil {
		return nil, errors.New("Invalid token")
	}
	if time.Now().UTC().After(token.CreationDate.Add(token.ExperesIn)) {
		return nil, errors.New("Token expired")
	}
	return token, nil
}

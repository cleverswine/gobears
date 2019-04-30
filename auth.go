package gobears

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

// ClaimsKey is the key into the http context for retrieving claims
const ClaimsKey = "claims"

// ClaimsType is a wrapper type for storing values in the http.Request context
type ClaimsType string

// Claims are an extension fo the jwt.StandardClaims
type Claims struct {
	jwt.StandardClaims
	Scopes []string `json:"scope,omitempty"`
}

// Auth implements http middleware for parsing and verifying oauth2 bearer tokens
type Auth struct {
	Issuer          string
	RequiredScopes  []string
	CustomValidator func(*Claims) error
	signingKeyCache *signingKeyCache
}

// New create a new Auth with the provided parameters
func New(issuer string, requiredScopes []string, signingKeyCacheLifeSpan time.Duration) *Auth {

	return &Auth{
		Issuer:          issuer,
		RequiredScopes:  requiredScopes,
		signingKeyCache: newSigningKeyCache(signingKeyCacheLifeSpan),
	}
}

// WithBearerToken is a middleware implementation that will look for a bearer token, parsie it, and verify it. If sussessful, the resulting Claims will be dropped into the request context as "claims"
func (j *Auth) WithBearerToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := tokenFromHeader(r)
		if tokenString != "" {
			// get and validate the token
			token, err := jwt.ParseWithClaims(tokenString, &Claims{}, j.verify)
			if err != nil {
				// log error?
			} else {
				r = r.WithContext(context.WithValue(r.Context(), ClaimsType(ClaimsKey), token.Claims.(*Claims)))
			}
		}
		next.ServeHTTP(w, r)
	}
}

func (j *Auth) verify(token *jwt.Token) (interface{}, error) {
	// get claims from token
	claims := token.Claims.(*Claims)
	if claims == nil {
		return nil, fmt.Errorf("Unable to get claims from token")
	}
	// Valid() checks the token's timestamp window
	validErr := claims.Valid()
	if validErr != nil {
		return nil, validErr
	}
	// validate scopes
	foundmatches := 0
	if len(j.RequiredScopes) > 0 {
		for i := 0; i < len(j.RequiredScopes); i++ {
			for k := 0; k < len(claims.Scopes); k++ {
				if claims.Scopes[k] == j.RequiredScopes[i] {
					foundmatches++
				}
			}
		}
	}
	if foundmatches != len(j.RequiredScopes) {
		return nil, fmt.Errorf("Required scopes (%v) not found in token. Found: %v", j.RequiredScopes, claims.Scopes)
	}
	// check the signing method
	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
	}
	// run custom validation, if specified
	if j.CustomValidator != nil {
		err := j.CustomValidator(claims)
		if err != nil {
			return nil, err
		}
	}
	// fetch the signing key
	kid, ok := token.Header["kid"].(string)
	if !ok || kid == "" {
		return nil, fmt.Errorf("failed to get kid header from token")
	}
	key, err := j.signingKeyCache.getSigningKey(claims.Issuer, kid)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func tokenFromHeader(r *http.Request) string {
	bearer := r.Header.Get("Authorization")
	if len(bearer) > 7 && strings.ToUpper(bearer[0:6]) == "BEARER" {
		return bearer[7:]
	}
	return ""
}

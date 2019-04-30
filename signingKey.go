package gobears

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/muesli/cache2go"
	jose "github.com/square/go-jose"
)

type signingKeyCache struct {
	lifeSpan time.Duration
	cache    *cache2go.CacheTable
}

const discoveryURI = "/.well-known/openid-configuration"

type openIDConfig struct {
	JwksURI string `json:"jwks_uri"`
}

func newSigningKeyCache(lifeSpan time.Duration) *signingKeyCache {
	return &signingKeyCache{
		lifeSpan: lifeSpan,
		cache:    cache2go.Cache("signingKeyCache"),
	}
}

func (s *signingKeyCache) getSigningKey(issuer, kid string) (*rsa.PublicKey, error) {
	cacheKey := issuer + kid
	cachedSigningKey, err := s.cache.Value(cacheKey)
	if err == nil {
		return cachedSigningKey.Data().(*rsa.PublicKey), nil
	}
	// get discovery document from issuer
	if strings.HasSuffix(issuer, "/") {
		strings.TrimSuffix(issuer, "/")
	}
	discoveryDoc := openIDConfig{}
	err = getFromURI(issuer+discoveryURI, &discoveryDoc)
	if err != nil {
		return nil, err
	}
	// get jwks keys from the endpoint specified in the discovery document
	jwks := &jose.JSONWebKeySet{}
	err = getFromURI(discoveryDoc.JwksURI, jwks)
	if err != nil {
		return nil, err
	}
	// get key(s) for the requested kid (key ID)
	jwkarr := jwks.Key(kid)
	if jwkarr == nil || len(jwkarr) == 0 {
		return nil, fmt.Errorf("Key with kid %s not found at issuer %s", kid, issuer)
	}
	// use the first key if multiple were specified
	jwk := jwkarr[0]
	signingKey, ok := jwk.Key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Key was not of expected type rsa.PublicKey. It was %T", jwk.Key)
	}
	// add to cache and return it
	s.cache.Add(cacheKey, s.lifeSpan, signingKey)
	return signingKey, nil
}

func getFromURI(uri string, result interface{}) error {
	client := &http.Client{}
	resp, err := client.Get(uri)
	if err != nil {
		return fmt.Errorf("Unable to GET %s : %s", uri, err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			b = []byte(err.Error())
		}
		return fmt.Errorf("Unable to GET %s : response status was [%s] and body was: %s", uri, resp.Status, string(b))
	}
	err = json.NewDecoder(resp.Body).Decode(result)
	if err != nil {
		return fmt.Errorf("Unable to deserialize response from %s : %s", uri, err.Error())
	}
	return nil
}

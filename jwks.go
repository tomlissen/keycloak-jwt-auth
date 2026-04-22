// JWKS fetching adapted from github.com/tpaulus/jwt-middleware (via github.com/team-carepay/traefik-jwt-plugin).
// Uses manual key construction instead of go-jose to avoid yaegi unmarshalling issues.
package keycloak_jwt_auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"time"
)

// jwksRetryDelay is the pause between JWKS fetch attempts. Overridable in tests.
var jwksRetryDelay = 500 * time.Millisecond

type jsonWebKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	Crv string `json:"crv,omitempty"`
}

type jsonWebKeySet struct {
	Keys []jsonWebKey `json:"keys"`
}

// FetchJWKS fetches public keys from the JWKS endpoint and returns a map keyed by kid.
func FetchJWKS(client *http.Client, jwksURL string) (map[string]interface{}, error) {
	keys, err, _ := doFetchJWKS(client, jwksURL)
	return keys, err
}

// fetchJWKSWithRetry calls doFetchJWKS up to maxAttempts times, retrying after
// jwksRetryDelay on transient errors (network failures and 5xx responses).
// Non-transient errors (4xx, malformed JSON) are returned immediately.
func fetchJWKSWithRetry(client *http.Client, jwksURL string, maxAttempts int) (map[string]interface{}, error) {
	var lastErr error
	for i := 0; i < maxAttempts; i++ {
		if i > 0 {
			time.Sleep(jwksRetryDelay)
		}
		keys, err, transient := doFetchJWKS(client, jwksURL)
		if err == nil {
			return keys, nil
		}
		lastErr = err
		if !transient {
			break
		}
	}
	return nil, lastErr
}

// doFetchJWKS performs a single JWKS fetch. The bool return indicates whether
// the error is transient and eligible for retry.
func doFetchJWKS(client *http.Client, jwksURL string) (map[string]interface{}, error, bool) {
	resp, err := client.Get(jwksURL)
	if err != nil {
		return nil, err, true
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("JWKS endpoint returned %s", resp.Status), true
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned %s", resp.Status), false
	}

	var jwks jsonWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err), false
	}

	keys := make(map[string]interface{}, len(jwks.Keys))
	for _, jwk := range jwks.Keys {
		kid := jwk.Kid
		if kid == "" {
			kid = jwkThumbprint(jwk)
		}
		key, err := parseJWK(jwk)
		if err != nil {
			continue
		}
		keys[kid] = key
	}

	return keys, nil, false
}

func parseJWK(jwk jsonWebKey) (interface{}, error) {
	switch jwk.Kty {
	case "RSA":
		nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
		if err != nil {
			return nil, fmt.Errorf("invalid RSA n: %w", err)
		}

		eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
		if err != nil {
			return nil, fmt.Errorf("invalid RSA e: %w", err)
		}

		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: int(new(big.Int).SetBytes(eBytes).Uint64()),
		}, nil

	case "EC":
		curve := ecCurve(jwk)

		xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
		if err != nil {
			return nil, fmt.Errorf("invalid EC x: %w", err)
		}

		yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
		if err != nil {
			return nil, fmt.Errorf("invalid EC y: %w", err)
		}

		return &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(yBytes),
		}, nil

	default:
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}
}

func ecCurve(jwk jsonWebKey) elliptic.Curve {
	switch jwk.Crv {
	case "P-384":
		return elliptic.P384()
	case "P-521":
		return elliptic.P521()
	default:
		switch jwk.Alg {
		case "ES384":
			return elliptic.P384()
		case "ES512":
			return elliptic.P521()
		default:
			return elliptic.P256()
		}
	}
}

func jwkThumbprint(jwk jsonWebKey) string {
	var text string

	switch jwk.Kty {
	case "RSA":
		text = fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`, jwk.E, jwk.N)
	case "EC":
		text = fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, jwk.X, jwk.Y)
	}

	sum := sha256.Sum256([]byte(text))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}

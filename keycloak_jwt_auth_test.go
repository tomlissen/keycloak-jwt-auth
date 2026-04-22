package keycloak_jwt_auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testClientID     = "my-client"
	testRequiredRole = "app-user"
)

// testKey wraps an RSA key pair for JWT signing and JWKS serving in tests.
type testKey struct {
	private *rsa.PrivateKey
	kid     string
}

func newTestKey(t *testing.T) *testKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return &testKey{private: priv, kid: "k1"}
}

func (k *testKey) sign(claims jwt.MapClaims) string {
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = k.kid
	s, err := tok.SignedString(k.private)
	if err != nil {
		panic(err)
	}
	return s
}

func (k *testKey) jwksBody() []byte {
	pub := &k.private.PublicKey
	body, _ := json.Marshal(map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"alg": "RS256",
				"use": "sig",
				"kid": k.kid,
				"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			},
		},
	})
	return body
}

// keycloakMock serves JWKS at /protocol/openid-connect/certs and a token at
// /protocol/openid-connect/token. Set accessToken before triggering a callback.
type keycloakMock struct {
	server      *httptest.Server
	key         *testKey
	accessToken string
}

func newKeycloakMock(t *testing.T, key *testKey) *keycloakMock {
	t.Helper()
	m := &keycloakMock{key: key}
	m.server = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		switch req.URL.Path {
		case "/protocol/openid-connect/certs":
			rw.Write(key.jwksBody())
		case "/protocol/openid-connect/token":
			json.NewEncoder(rw).Encode(map[string]string{"access_token": m.accessToken})
		default:
			http.NotFound(rw, req)
		}
	}))
	t.Cleanup(m.server.Close)
	return m
}

func (m *keycloakMock) issuerURL() string { return m.server.URL }

func minConfig(issuerURL string) *Config {
	return &Config{
		KeycloakIssuerURL: issuerURL,
		KeycloakClientID:  testClientID,
		KeycloakScopes:    "openid",
		TokenCookieName:   "_kc_token",
		TokenCookieSecure: false,
		CallbackPath:      "/sso/callback",
		LogoutPath:        "/sso/logout",
	}
}

func newTestMiddleware(t *testing.T, cfg *Config, next http.Handler) *Middleware {
	t.Helper()
	if next == nil {
		next = http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
			rw.WriteHeader(http.StatusOK)
		})
	}
	h, err := New(context.Background(), next, cfg, "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m, ok := h.(*Middleware)
	if !ok {
		t.Fatal("expected *Middleware")
	}
	return m
}

func validClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"azp": testClientID,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
}

// --- Config validation ---

func TestNewMissingIssuerURL(t *testing.T) {
	_, err := New(context.Background(), http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {}), &Config{
		KeycloakClientID: testClientID,
	}, "test")
	if err == nil {
		t.Fatal("expected error for missing keycloakIssuerURL")
	}
}

func TestNewMissingClientID(t *testing.T) {
	_, err := New(context.Background(), http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {}), &Config{
		KeycloakIssuerURL: "https://keycloak.example.com/realms/test",
	}, "test")
	if err == nil {
		t.Fatal("expected error for missing keycloakClientId")
	}
}

// --- shouldStartLogin ---

func TestShouldStartLoginSecFetchModeNavigate(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	if !shouldStartLogin(req) {
		t.Fatal("expected true for Sec-Fetch-Mode: navigate")
	}
}

func TestShouldStartLoginTextHTML(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/page", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	if !shouldStartLogin(req) {
		t.Fatal("expected true for Accept: text/html")
	}
}

func TestShouldStartLoginAPIRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/data", nil)
	req.Header.Set("Accept", "application/json")
	if shouldStartLogin(req) {
		t.Fatal("expected false for application/json Accept")
	}
}

func TestShouldStartLoginPost(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/submit", nil)
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	if shouldStartLogin(req) {
		t.Fatal("expected false for POST request")
	}
}

// --- Unauthenticated requests ---

func TestBrowserRequestRedirectsToKeycloak(t *testing.T) {
	key := newTestKey(t)
	kc := newKeycloakMock(t, key)
	m := newTestMiddleware(t, minConfig(kc.issuerURL()), nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	rr := httptest.NewRecorder()

	m.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rr.Code)
	}
	location := rr.Header().Get("Location")
	if !strings.HasPrefix(location, kc.issuerURL()+"/protocol/openid-connect/auth?") {
		t.Fatalf("unexpected redirect: %s", location)
	}
	if !strings.Contains(location, "client_id="+testClientID) {
		t.Fatalf("missing client_id in redirect: %s", location)
	}

	var stateCookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == m.stateCookieName() {
			stateCookie = c
			break
		}
	}
	if stateCookie == nil {
		t.Fatalf("expected state cookie %q to be set", m.stateCookieName())
	}
}

func TestAPIRequestReturns401(t *testing.T) {
	key := newTestKey(t)
	kc := newKeycloakMock(t, key)
	m := newTestMiddleware(t, minConfig(kc.issuerURL()), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/data", nil)
	req.Header.Set("Accept", "application/json")
	rr := httptest.NewRecorder()

	m.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	if rr.Header().Get("Location") != "" {
		t.Fatal("expected no redirect for API request")
	}
}

func TestPostWithoutTokenReturns401(t *testing.T) {
	key := newTestKey(t)
	kc := newKeycloakMock(t, key)
	m := newTestMiddleware(t, minConfig(kc.issuerURL()), nil)

	req := httptest.NewRequest(http.MethodPost, "/submit", nil)
	rr := httptest.NewRecorder()

	m.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

// --- Token validation ---

func TestValidTokenCookiePassesThrough(t *testing.T) {
	key := newTestKey(t)
	kc := newKeycloakMock(t, key)
	var nextCalled bool
	m := newTestMiddleware(t, minConfig(kc.issuerURL()), http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		rw.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "_kc_token", Value: key.sign(validClaims())})
	rr := httptest.NewRecorder()

	m.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !nextCalled {
		t.Fatal("expected next handler to be called")
	}
}

func TestValidBearerTokenPassesThrough(t *testing.T) {
	key := newTestKey(t)
	kc := newKeycloakMock(t, key)
	var nextCalled bool
	m := newTestMiddleware(t, minConfig(kc.issuerURL()), http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		rw.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+key.sign(validClaims()))
	rr := httptest.NewRecorder()

	m.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !nextCalled {
		t.Fatal("expected next handler to be called")
	}
}

func TestWrongClientIDRejected(t *testing.T) {
	key := newTestKey(t)
	kc := newKeycloakMock(t, key)
	m := newTestMiddleware(t, minConfig(kc.issuerURL()), nil)

	claims := jwt.MapClaims{
		"azp": "other-client",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("Accept", "application/json")
	req.AddCookie(&http.Cookie{Name: "_kc_token", Value: key.sign(claims)})
	rr := httptest.NewRecorder()

	m.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestAudienceClaimMatchesClientID(t *testing.T) {
	key := newTestKey(t)
	kc := newKeycloakMock(t, key)
	var nextCalled bool
	m := newTestMiddleware(t, minConfig(kc.issuerURL()), http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		rw.WriteHeader(http.StatusOK)
	}))

	claims := jwt.MapClaims{
		"aud": testClientID,
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "_kc_token", Value: key.sign(claims)})
	rr := httptest.NewRecorder()

	m.ServeHTTP(rr, req)

	if !nextCalled {
		t.Fatalf("expected aud claim to satisfy clientID check, got %d", rr.Code)
	}
}

func TestRequiredRealmRoleGrantsAccess(t *testing.T) {
	key := newTestKey(t)
	kc := newKeycloakMock(t, key)
	cfg := minConfig(kc.issuerURL())
	cfg.RequiredRole = testRequiredRole
	var nextCalled bool
	m := newTestMiddleware(t, cfg, http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		rw.WriteHeader(http.StatusOK)
	}))

	claims := jwt.MapClaims{
		"azp": testClientID,
		"exp": time.Now().Add(time.Hour).Unix(),
		"realm_access": map[string]interface{}{
			"roles": []interface{}{testRequiredRole, "other-role"},
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "_kc_token", Value: key.sign(claims)})
	rr := httptest.NewRecorder()

	m.ServeHTTP(rr, req)

	if !nextCalled {
		t.Fatalf("expected realm role to grant access, got %d", rr.Code)
	}
}

func TestRequiredClientRoleGrantsAccess(t *testing.T) {
	key := newTestKey(t)
	kc := newKeycloakMock(t, key)
	cfg := minConfig(kc.issuerURL())
	cfg.RequiredRole = testRequiredRole
	var nextCalled bool
	m := newTestMiddleware(t, cfg, http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		rw.WriteHeader(http.StatusOK)
	}))

	claims := jwt.MapClaims{
		"azp": testClientID,
		"exp": time.Now().Add(time.Hour).Unix(),
		"resource_access": map[string]interface{}{
			testClientID: map[string]interface{}{
				"roles": []interface{}{testRequiredRole},
			},
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "_kc_token", Value: key.sign(claims)})
	rr := httptest.NewRecorder()

	m.ServeHTTP(rr, req)

	if !nextCalled {
		t.Fatalf("expected resource_access role to grant access, got %d", rr.Code)
	}
}

func TestMissingRequiredRoleBlocks(t *testing.T) {
	key := newTestKey(t)
	kc := newKeycloakMock(t, key)
	cfg := minConfig(kc.issuerURL())
	cfg.RequiredRole = testRequiredRole
	m := newTestMiddleware(t, cfg, nil)

	claims := jwt.MapClaims{
		"azp": testClientID,
		"exp": time.Now().Add(time.Hour).Unix(),
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"some-other-role"},
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("Accept", "application/json")
	req.AddCookie(&http.Cookie{Name: "_kc_token", Value: key.sign(claims)})
	rr := httptest.NewRecorder()

	m.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing role, got %d", rr.Code)
	}
}

func TestExpiredTokenClearsCookieAndRedirects(t *testing.T) {
	key := newTestKey(t)
	kc := newKeycloakMock(t, key)
	m := newTestMiddleware(t, minConfig(kc.issuerURL()), nil)

	claims := jwt.MapClaims{
		"azp": testClientID,
		"exp": time.Now().Add(-time.Hour).Unix(),
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.AddCookie(&http.Cookie{Name: "_kc_token", Value: key.sign(claims)})
	rr := httptest.NewRecorder()

	m.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302 after expired token, got %d", rr.Code)
	}

	// The stale token cookie must be cleared (MaxAge=0 in Set-Cookie means delete).
	cleared := false
	for _, c := range rr.Result().Cookies() {
		if c.Name == "_kc_token" {
			cleared = c.MaxAge <= 0
		}
	}
	if !cleared {
		t.Fatal("expected stale token cookie to be cleared in response")
	}
}

// --- Callback ---

func TestCallbackMissingParameters(t *testing.T) {
	key := newTestKey(t)
	kc := newKeycloakMock(t, key)
	m := newTestMiddleware(t, minConfig(kc.issuerURL()), nil)

	req := httptest.NewRequest(http.MethodGet, "/sso/callback", nil)
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestCallbackKeycloakError(t *testing.T) {
	key := newTestKey(t)
	kc := newKeycloakMock(t, key)
	m := newTestMiddleware(t, minConfig(kc.issuerURL()), nil)

	req := httptest.NewRequest(http.MethodGet, "/sso/callback?error=access_denied", nil)
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestCallbackInvalidStateNonce(t *testing.T) {
	key := newTestKey(t)
	kc := newKeycloakMock(t, key)
	m := newTestMiddleware(t, minConfig(kc.issuerURL()), nil)

	cookieRR := httptest.NewRecorder()
	err := m.writeJSONCookie(cookieRR, m.stateCookieName(), statePayload{
		Nonce:     "real-nonce",
		ReturnTo:  "/",
		ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
	}, 10*time.Minute)
	if err != nil {
		t.Fatalf("writeSignedCookie: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/sso/callback?code=abc&state=wrong-nonce", nil)
	req.AddCookie(cookieRR.Result().Cookies()[0])
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong nonce, got %d", rr.Code)
	}
}

func TestCallbackExpiredState(t *testing.T) {
	key := newTestKey(t)
	kc := newKeycloakMock(t, key)
	m := newTestMiddleware(t, minConfig(kc.issuerURL()), nil)

	cookieRR := httptest.NewRecorder()
	err := m.writeJSONCookie(cookieRR, m.stateCookieName(), statePayload{
		Nonce:     "my-nonce",
		ReturnTo:  "/",
		ExpiresAt: time.Now().Add(-time.Minute).Unix(),
	}, 10*time.Minute)
	if err != nil {
		t.Fatalf("writeSignedCookie: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/sso/callback?code=abc&state=my-nonce", nil)
	req.AddCookie(cookieRR.Result().Cookies()[0])
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for expired state, got %d", rr.Code)
	}
}

func TestCallbackSuccess(t *testing.T) {
	key := newTestKey(t)
	kc := newKeycloakMock(t, key)

	accessToken := key.sign(jwt.MapClaims{
		"azp": testClientID,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	kc.accessToken = accessToken

	m := newTestMiddleware(t, minConfig(kc.issuerURL()), nil)

	cookieRR := httptest.NewRecorder()
	err := m.writeJSONCookie(cookieRR, m.stateCookieName(), statePayload{
		Nonce:     "mynonce",
		ReturnTo:  "/dashboard",
		ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
	}, 10*time.Minute)
	if err != nil {
		t.Fatalf("writeSignedCookie: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/sso/callback?code=authcode&state=mynonce", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	req.AddCookie(cookieRR.Result().Cookies()[0])
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", rr.Code, rr.Body.String())
	}
	location := rr.Header().Get("Location")
	if !strings.HasSuffix(location, "/dashboard") {
		t.Fatalf("expected redirect to /dashboard, got: %s", location)
	}

	var tokenCookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == "_kc_token" {
			tokenCookie = c
			break
		}
	}
	if tokenCookie == nil {
		t.Fatal("expected token cookie to be set after successful callback")
	}
	if tokenCookie.Value != accessToken {
		t.Fatal("token cookie value does not match the issued access token")
	}
}

// --- Logout ---

func TestLogoutRedirectsToKeycloak(t *testing.T) {
	key := newTestKey(t)
	kc := newKeycloakMock(t, key)
	m := newTestMiddleware(t, minConfig(kc.issuerURL()), nil)

	req := httptest.NewRequest(http.MethodGet, "/sso/logout", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rr.Code)
	}
	location := rr.Header().Get("Location")
	if !strings.HasPrefix(location, kc.issuerURL()+"/protocol/openid-connect/logout?") {
		t.Fatalf("unexpected logout redirect: %s", location)
	}
	if !strings.Contains(location, "client_id="+testClientID) {
		t.Fatalf("missing client_id in logout URL: %s", location)
	}
	if !strings.Contains(location, "post_logout_redirect_uri=") {
		t.Fatalf("missing post_logout_redirect_uri in logout URL: %s", location)
	}
}

// --- jwtTTL ---

func TestJwtTTLExtractsExpiry(t *testing.T) {
	key := newTestKey(t)
	tokenStr := key.sign(jwt.MapClaims{
		"azp": testClientID,
		"exp": time.Now().Add(2 * time.Hour).Unix(),
	})
	ttl := jwtTTL(tokenStr)
	if ttl < 115*time.Minute || ttl > 125*time.Minute {
		t.Fatalf("expected TTL ~2h, got %v", ttl)
	}
}

func TestJwtTTLFallbackForMalformedToken(t *testing.T) {
	ttl := jwtTTL("not.a.jwt")
	if ttl != time.Hour {
		t.Fatalf("expected 1h fallback for malformed token, got %v", ttl)
	}
}

// --- Negative cache ---

// TestFetchCooldownBlocksRotatingKids verifies that flooding with distinct unknown kids
// does not trigger more than one JWKS fetch per cooldown window.
func TestFetchCooldownBlocksRotatingKids(t *testing.T) {
	knownKey := newTestKey(t)
	var fetchCount int

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		if req.URL.Path == "/protocol/openid-connect/certs" {
			fetchCount++
			rw.Write(knownKey.jwksBody())
		}
	}))
	t.Cleanup(server.Close)

	m := newTestMiddleware(t, minConfig(server.URL), nil)

	for i := 0; i < 10; i++ {
		attackerKey := newTestKey(t)
		attackerKey.kid = fmt.Sprintf("foreign-kid-%d", i)
		token := attackerKey.sign(jwt.MapClaims{
			"azp": testClientID,
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		req := httptest.NewRequest(http.MethodGet, "/api", nil)
		req.Header.Set("Accept", "application/json")
		req.AddCookie(&http.Cookie{Name: "_kc_token", Value: token})
		m.ServeHTTP(httptest.NewRecorder(), req)
	}

	if fetchCount != 1 {
		t.Fatalf("expected exactly 1 JWKS fetch for rotating foreign kids, got %d", fetchCount)
	}
}

// --- Retry ---

// TestRetryOnTransientJWKSError verifies that a transient 5xx from the JWKS endpoint
// is retried and the request ultimately succeeds when Keycloak recovers.
func TestRetryOnTransientJWKSError(t *testing.T) {
	jwksRetryDelay = 5 * time.Millisecond
	t.Cleanup(func() { jwksRetryDelay = 500 * time.Millisecond })

	key := newTestKey(t)
	var callCount int

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		switch req.URL.Path {
		case "/protocol/openid-connect/certs":
			callCount++
			if callCount < 3 {
				rw.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			rw.Write(key.jwksBody())
		default:
			http.NotFound(rw, req)
		}
	}))
	t.Cleanup(server.Close)

	var nextCalled bool
	m := newTestMiddleware(t, minConfig(server.URL), http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		rw.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "_kc_token", Value: key.sign(validClaims())})
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)

	if !nextCalled {
		t.Fatalf("expected request to succeed after retries, got %d", rr.Code)
	}
	if callCount != 3 {
		t.Fatalf("expected 3 JWKS fetch attempts, got %d", callCount)
	}
}

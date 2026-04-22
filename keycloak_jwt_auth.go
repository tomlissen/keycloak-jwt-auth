package keycloak_jwt_auth

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Config holds all middleware configuration values supplied via the Traefik dynamic config.
type Config struct {
	// KeycloakIssuerURL is the base URL of the Keycloak realm,
	// e.g. https://keycloak.example.com/realms/myrealm.
	// All OIDC endpoints (/auth, /token, /certs, /logout) are constructed from this.
	KeycloakIssuerURL string `json:"keycloakIssuerURL"`

	// KeycloakClientID is the client ID registered in Keycloak.
	// It is sent in the OIDC authorization request and used to verify
	// the azp/aud claims of every incoming JWT.
	KeycloakClientID string `json:"keycloakClientId"`

	// KeycloakScopes is the space-separated list of OAuth2 scopes to request.
	// Defaults to "openid".
	KeycloakScopes string `json:"keycloakScopes"`

	// RequiredRole is the role the authenticated user must have.
	// The plugin checks realm_access.roles (realm role) and
	// resource_access[clientId].roles (client role) in the JWT claims.
	// Leave empty to allow any authenticated user regardless of role.
	RequiredRole string `json:"requiredRole"`

	// TokenCookieName is the name of the cookie used to store the JWT access token
	// after a successful login. Defaults to "_kc_token".
	TokenCookieName string `json:"tokenCookieName"`

	// TokenCookieSecure controls the Secure flag on the token and state cookies.
	// Set to false only in local HTTP development environments.
	TokenCookieSecure bool `json:"tokenCookieSecure"`

	// CallbackPath is the path on the protected host that Keycloak redirects back to
	// after the user authenticates. Must be registered as a valid redirect URI in Keycloak.
	// Defaults to "/auth/callback".
	CallbackPath string `json:"callbackPath"`

	// LogoutPath is the path that clears the token cookie and redirects the browser to
	// Keycloak's end-session endpoint. Defaults to "/auth/logout".
	LogoutPath string `json:"logoutPath"`

	// InsecureSkipTLSVerify disables TLS certificate verification for all outbound
	// requests to Keycloak (token exchange and JWKS fetch).
	// Only use in development with self-signed certificates.
	InsecureSkipTLSVerify bool `json:"insecureSkipTLSVerify"`
}

// CreateConfig returns a Config populated with default values.
// Traefik calls this before unmarshalling the user-supplied configuration on top of it.
func CreateConfig() *Config {
	return &Config{
		KeycloakScopes:    "openid",
		TokenCookieName:   "_kc_token",
		TokenCookieSecure: true,
		CallbackPath:      "/sso/callback",
		LogoutPath:        "/sso/logout",
	}
}

// statePayload is stored in the CSRF state cookie during the OIDC login flow.
// It ties the callback request back to the original browser request and prevents
// CSRF by binding the nonce to the state query parameter returned by Keycloak.
type statePayload struct {
	Nonce     string `json:"nonce"`
	ReturnTo  string `json:"returnTo"`
	ExpiresAt int64  `json:"expiresAt"`
}

// kcTokenResponse is the subset of the Keycloak token endpoint response that we need.
type kcTokenResponse struct {
	AccessToken string `json:"access_token"`
}

// jwksCache is an in-memory store for Keycloak public keys keyed by kid.
// Keys are fetched lazily on first use and refreshed whenever an unknown kid is encountered,
// which naturally handles Keycloak key rotation. lastFetchAt rate-limits fetches to at most
// one per fetchCooldown regardless of how many distinct unknown kids arrive.
type jwksCache struct {
	mu            sync.RWMutex
	keys          map[string]interface{}
	lastFetchAt   time.Time
	fetchCooldown time.Duration
}

// Middleware is the Traefik middleware handler. One instance is created per route that
// references this plugin.
type Middleware struct {
	next   http.Handler
	name   string
	config *Config
	client *http.Client
	jwks   *jwksCache
	parser *jwt.Parser
}

// New is called by Traefik once when the middleware is instantiated.
// It validates required config, builds the HTTP client (with optional TLS skip),
// and returns the middleware handler.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config == nil {
		config = CreateConfig()
	}

	switch {
	case strings.TrimSpace(config.KeycloakIssuerURL) == "":
		return nil, errors.New("keycloakIssuerURL is required")
	case strings.TrimSpace(config.KeycloakClientID) == "":
		return nil, errors.New("keycloakClientId is required")
	}

	if !strings.HasPrefix(config.CallbackPath, "/") {
		config.CallbackPath = "/" + config.CallbackPath
	}

	if config.LogoutPath != "" && !strings.HasPrefix(config.LogoutPath, "/") {
		config.LogoutPath = "/" + config.LogoutPath
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if config.InsecureSkipTLSVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return &Middleware{
		next:   next,
		name:   name,
		config: config,
		client: &http.Client{Timeout: 15 * time.Second, Transport: transport},
		jwks: &jwksCache{
				keys:          make(map[string]interface{}),
				fetchCooldown: 1 * time.Second,
			},
		parser: jwt.NewParser(
			jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}),
		),
	}, nil
}

// ServeHTTP is the main entry point for every request passing through the middleware.
// It routes callback and logout paths to their dedicated handlers, then attempts to
// validate an existing JWT. If no valid token is found, browser requests are redirected
// to Keycloak and API requests receive 401.
func (m *Middleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	switch req.URL.Path {
	case m.config.CallbackPath:
		m.handleCallback(rw, req)
		return
	case m.config.LogoutPath:
		m.handleLogout(rw, req)
		return
	}

	if tokenStr := m.extractToken(req); tokenStr != "" {
		if m.validateToken(tokenStr) {
			m.next.ServeHTTP(rw, req)
			return
		}
		// Clear the stale or invalid token cookie so the browser doesn't keep sending it
		// on every request, causing a JWKS fetch on each one.
		m.clearCookie(rw, m.config.TokenCookieName)
	}

	if !shouldStartLogin(req) {
		m.writeError(rw, http.StatusUnauthorized, "authentication required")
		return
	}

	m.startLogin(rw, req)
}

// startLogin begins the OIDC authorization code flow. It generates a random nonce,
// stores it alongside the original request URL in an HMAC-signed state cookie (valid
// for 10 minutes), then redirects the browser to Keycloak's authorization endpoint.
func (m *Middleware) startLogin(rw http.ResponseWriter, req *http.Request) {
	nonce, err := randomToken(32)
	if err != nil {
		m.writeError(rw, http.StatusInternalServerError, "failed to generate login state")
		return
	}

	state := statePayload{
		Nonce:     nonce,
		ReturnTo:  requestTarget(req),
		ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
	}

	if err := m.writeJSONCookie(rw, m.stateCookieName(), state, 10*time.Minute); err != nil {
		m.writeError(rw, http.StatusInternalServerError, "failed to persist login state")
		return
	}

	query := url.Values{}
	query.Set("client_id", m.config.KeycloakClientID)
	query.Set("response_type", "code")
	query.Set("scope", m.config.KeycloakScopes)
	query.Set("redirect_uri", m.externalBaseURL(req)+m.config.CallbackPath)
	query.Set("state", nonce)

	http.Redirect(rw, req, m.issuerEndpoint("/protocol/openid-connect/auth")+"?"+query.Encode(), http.StatusFound)
}

// handleCallback processes the redirect from Keycloak after the user authenticates.
// It validates the state parameter against the CSRF state cookie, exchanges the
// authorization code for an access token, stores the token in an HttpOnly cookie,
// then redirects the browser back to the original URL.
func (m *Middleware) handleCallback(rw http.ResponseWriter, req *http.Request) {
	defer m.clearCookie(rw, m.stateCookieName())

	if errMsg := req.URL.Query().Get("error"); errMsg != "" {
		m.writeError(rw, http.StatusUnauthorized, "keycloak rejected authentication: "+errMsg)
		return
	}

	code := req.URL.Query().Get("code")
	stateToken := req.URL.Query().Get("state")

	if code == "" || stateToken == "" {
		m.writeError(rw, http.StatusBadRequest, "missing OIDC callback parameters")
		return
	}

	state, ok := m.readState(req)
	if !ok || state.Nonce != stateToken || state.ExpiresAt < time.Now().Unix() {
		m.writeError(rw, http.StatusUnauthorized, "invalid or expired login state")
		return
	}

	tr, err := m.exchangeCode(req.Context(), code, m.externalBaseURL(req)+m.config.CallbackPath)
	if err != nil {
		m.writeError(rw, http.StatusBadGateway, err.Error())
		return
	}

	// Set the cookie MaxAge to match the token's own expiry so they expire together.
	ttl := jwtTTL(tr.AccessToken)
	http.SetCookie(rw, &http.Cookie{
		Name:     m.config.TokenCookieName,
		Value:    tr.AccessToken,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		Expires:  time.Now().Add(ttl),
		HttpOnly: true,
		Secure:   m.config.TokenCookieSecure,
		SameSite: http.SameSiteLaxMode,
	})

	returnTo := state.ReturnTo
	if returnTo == "" {
		returnTo = "/"
	}

	http.Redirect(rw, req, m.externalBaseURL(req)+returnTo, http.StatusFound)
}

// handleLogout clears the token and state cookies then redirects the browser to
// Keycloak's end-session endpoint, which invalidates the Keycloak session server-side
// and then sends the user back to the application root.
func (m *Middleware) handleLogout(rw http.ResponseWriter, req *http.Request) {
	m.clearCookie(rw, m.config.TokenCookieName)
	m.clearCookie(rw, m.stateCookieName())

	query := url.Values{}
	query.Set("client_id", m.config.KeycloakClientID)
	query.Set("post_logout_redirect_uri", m.externalBaseURL(req)+"/")

	http.Redirect(rw, req, m.issuerEndpoint("/protocol/openid-connect/logout")+"?"+query.Encode(), http.StatusFound)
}

// validateToken parses the JWT, verifies its signature via the JWKS cache, then checks
// that the token was issued for the configured client (azp/aud) and that the user
// holds the required role (if configured). Returns false for any failure so the
// caller can treat all invalid tokens uniformly.
func (m *Middleware) validateToken(tokenStr string) bool {
	token, err := m.parser.ParseWithClaims(tokenStr, jwt.MapClaims{}, m.getKey)
	if err != nil || !token.Valid {
		return false
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return false
	}

	if !m.hasClientID(claims) {
		return false
	}

	if m.config.RequiredRole != "" && !m.hasRole(claims) {
		return false
	}

	return true
}

// hasClientID returns true if the JWT was issued for the configured client.
// Keycloak sets azp (authorized party) on access tokens issued to a single confidential
// or public client. The aud (audience) claim is also checked as a fallback since some
// Keycloak configurations populate it instead of, or in addition to, azp.
func (m *Middleware) hasClientID(claims jwt.MapClaims) bool {
	if azp, ok := claims["azp"].(string); ok && azp == m.config.KeycloakClientID {
		return true
	}

	switch aud := claims["aud"].(type) {
	case string:
		return aud == m.config.KeycloakClientID
	case []interface{}:
		for _, a := range aud {
			if s, ok := a.(string); ok && s == m.config.KeycloakClientID {
				return true
			}
		}
	}

	return false
}

// hasRole returns true if the user holds the required role in either the realm-level
// roles (realm_access.roles) or the client-level roles (resource_access[clientId].roles).
// Checking both allows the required role to be assigned at either level in Keycloak.
func (m *Middleware) hasRole(claims jwt.MapClaims) bool {
	role := m.config.RequiredRole

	if realmAccess, ok := claims["realm_access"].(map[string]interface{}); ok {
		if roles, ok := realmAccess["roles"].([]interface{}); ok {
			for _, r := range roles {
				if s, ok := r.(string); ok && s == role {
					return true
				}
			}
		}
	}

	if resourceAccess, ok := claims["resource_access"].(map[string]interface{}); ok {
		if clientAccess, ok := resourceAccess[m.config.KeycloakClientID].(map[string]interface{}); ok {
			if roles, ok := clientAccess["roles"].([]interface{}); ok {
				for _, r := range roles {
					if s, ok := r.(string); ok && s == role {
						return true
					}
				}
			}
		}
	}

	return false
}

// extractToken tries to find a JWT in the request, preferring the token cookie over
// the Authorization header so that browser sessions (which use the cookie) take
// priority, while API clients can still pass a Bearer token in the header.
func (m *Middleware) extractToken(req *http.Request) string {
	if m.config.TokenCookieName != "" {
		if cookie, err := req.Cookie(m.config.TokenCookieName); err == nil && cookie.Value != "" {
			return cookie.Value
		}
	}

	if auth := req.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimSpace(auth[7:])
	}

	return ""
}

// getKey is the jwt.Keyfunc passed to the JWT parser. It resolves the signing key for
// a token using the kid header field. Keys are looked up from the in-memory JWKS cache;
// if the kid is not cached, the JWKS endpoint is fetched (with up to 3 attempts on
// transient errors) and the cache is replaced. A double-checked lock prevents redundant
// fetches under concurrent requests. A fetchCooldown rate-limits JWKS fetches to at most
// one per second, preventing a flood of unknown kids from hammering Keycloak.
func (m *Middleware) getKey(token *jwt.Token) (interface{}, error) {
	kid, _ := token.Header["kid"].(string)

	m.jwks.mu.RLock()
	key, ok := m.jwks.keys[kid]
	m.jwks.mu.RUnlock()

	if ok {
		return key, nil
	}

	m.jwks.mu.Lock()
	defer m.jwks.mu.Unlock()

	// Re-check after acquiring the write lock: another goroutine may have already
	// fetched the keys while we were waiting.
	if key, ok = m.jwks.keys[kid]; ok {
		return key, nil
	}

	// Rate limit: at most one JWKS fetch per fetchCooldown regardless of how many
	// distinct unknown kids arrive (e.g. from a foreign-issuer flood attack).
	if !m.jwks.lastFetchAt.IsZero() && time.Since(m.jwks.lastFetchAt) < m.jwks.fetchCooldown {
		return nil, fmt.Errorf("key %q not found in JWKS", kid)
	}

	keys, err := fetchJWKSWithRetry(m.client, m.issuerEndpoint("/protocol/openid-connect/certs"), 3)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	m.jwks.keys = keys
	m.jwks.lastFetchAt = time.Now()

	if key, ok = keys[kid]; ok {
		return key, nil
	}

	// Fallback for tokens that omit kid when there is exactly one key in the JWKS.
	if kid == "" && len(keys) == 1 {
		for _, k := range keys {
			return k, nil
		}
	}

	return nil, fmt.Errorf("key %q not found in JWKS", kid)
}

// exchangeCode sends the authorization code to Keycloak's token endpoint and returns
// the access token. The Keycloak client must be configured as public (no client secret).
func (m *Middleware) exchangeCode(ctx context.Context, code, redirectURI string) (*kcTokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", m.config.KeycloakClientID)
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.issuerEndpoint("/protocol/openid-connect/token"), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to build token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("keycloak token endpoint returned %s", resp.Status)
	}

	var tr kcTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	if tr.AccessToken == "" {
		return nil, errors.New("token response missing access_token")
	}

	return &tr, nil
}

// readState reads and verifies the CSRF state cookie, returning the parsed payload.
func (m *Middleware) readState(req *http.Request) (*statePayload, bool) {
	var payload statePayload
	if !m.readJSONCookie(req, m.stateCookieName(), &payload) {
		return nil, false
	}

	return &payload, true
}

// writeJSONCookie serialises payload to JSON, base64-encodes it, and sets the cookie.
func (m *Middleware) writeJSONCookie(rw http.ResponseWriter, name string, payload interface{}, ttl time.Duration) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	http.SetCookie(rw, &http.Cookie{
		Name:     name,
		Value:    base64.RawURLEncoding.EncodeToString(raw),
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		Expires:  time.Now().Add(ttl),
		HttpOnly: true,
		Secure:   m.config.TokenCookieSecure,
		SameSite: http.SameSiteLaxMode,
	})

	return nil
}

// readJSONCookie reads the named cookie, base64-decodes it, and unmarshals the JSON
// payload into target. Returns false if the cookie is missing or malformed.
func (m *Middleware) readJSONCookie(req *http.Request, name string, target interface{}) bool {
	cookie, err := req.Cookie(name)
	if err != nil {
		return false
	}

	payload, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return false
	}

	return json.Unmarshal(payload, target) == nil
}

// clearCookie expires the named cookie immediately by setting MaxAge to -1.
func (m *Middleware) clearCookie(rw http.ResponseWriter, name string) {
	http.SetCookie(rw, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   m.config.TokenCookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

// issuerEndpoint appends path to the configured Keycloak issuer URL,
// stripping any trailing slash first to avoid double slashes.
func (m *Middleware) issuerEndpoint(path string) string {
	return strings.TrimRight(m.config.KeycloakIssuerURL, "/") + path
}

// externalBaseURL reconstructs the public-facing base URL of the request
// using X-Forwarded-Proto and X-Forwarded-Host headers set by Traefik.
// This is used to build the redirect_uri and returnTo URLs that must reference
// the host the browser sees, not Traefik's internal address.
func (m *Middleware) externalBaseURL(req *http.Request) string {
	scheme := req.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		if req.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}

	host := req.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = req.Host
	}

	return scheme + "://" + host
}

// writeError writes a plain-text error response prefixed with the middleware name.
func (m *Middleware) writeError(rw http.ResponseWriter, status int, message string) {
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	rw.WriteHeader(status)
	_, _ = rw.Write([]byte(m.name + ": " + message))
}

// stateCookieName returns the name used for the CSRF state cookie, derived from the
// token cookie name so they share a consistent namespace.
func (m *Middleware) stateCookieName() string {
	return m.config.TokenCookieName + "_state"
}

// jwtTTL extracts the exp claim from a raw JWT string without verifying the signature.
// This is used only to set the cookie MaxAge so the cookie and the token expire together.
// Security is not a concern here because the signature is fully verified on every request.
func jwtTTL(tokenStr string) time.Duration {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return time.Hour
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Hour
	}

	var claims struct {
		Exp int64 `json:"exp"`
	}

	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp == 0 {
		return time.Hour
	}

	ttl := time.Until(time.Unix(claims.Exp, 0))
	if ttl <= 0 {
		return time.Minute
	}

	return ttl
}

// shouldStartLogin returns true only for browser navigation requests so that API clients
// (XHR, fetch, curl) receive a 401 rather than an HTML redirect page they cannot follow.
// Detection relies on Sec-Fetch-Mode: navigate (set by all modern browsers) with a
// fallback to Accept: text/html for older browsers.
func shouldStartLogin(req *http.Request) bool {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return false
	}

	if strings.EqualFold(req.Header.Get("Sec-Fetch-Mode"), "navigate") {
		return true
	}

	accept := strings.ToLower(req.Header.Get("Accept"))

	return strings.Contains(accept, "text/html") || (accept == "" && req.URL.Path == "/")
}

// requestTarget returns the full request URI (path + query) to use as the post-login
// return address, falling back to "/" if the URI is empty.
func requestTarget(req *http.Request) string {
	target := req.URL.RequestURI()
	if target == "" {
		return "/"
	}

	return target
}

// randomToken generates a cryptographically random URL-safe base64 string of the
// given byte length, used for CSRF nonces.
func randomToken(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(buf), nil
}


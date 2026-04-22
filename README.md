# keycloak-jwt-auth

A Traefik middleware plugin that protects routes with Keycloak OIDC authentication and JWT role-based access control.

## How it works

```
Browser                       Traefik (plugin)              Keycloak
  |                                  |                           |
  |-- GET /protected --------------->|                           |
  |                                  |-- no JWT / invalid JWT    |
  |<-- 302 /auth/callback? ----------|-- redirect to Keycloak -->|
  |                                  |                           |
  |-- GET /auth/callback?code=... -->|                           |
  |                                  |-- POST /token ----------->|
  |                                  |<-- access_token ----------|
  |<-- 302 /protected + Set-Cookie --|                           |
  |                                  |                           |
  |-- GET /protected + Cookie ------>|                           |
  |                                  |-- validate JWT (JWKS)     |
  |                                  |-- check azp / aud         |
  |                                  |-- check role              |
  |<-- 200 (proxied) ----------------|                           |
```

On each request the plugin:

1. Extracts the JWT from the token cookie or `Authorization: Bearer` header.
2. Validates the JWT signature against Keycloak's JWKS endpoint (`/protocol/openid-connect/certs`). Keys are cached in memory and refreshed automatically when an unknown `kid` is encountered. Fetches are rate-limited to at most one per second and retried up to three times on transient errors.
3. Checks that `azp` or `aud` in the JWT equals `keycloakClientId`.
4. If `requiredRole` is set, checks `realm_access.roles` and `resource_access[clientId].roles` in the JWT claims.
5. If any check fails, browser requests (detected via `Sec-Fetch-Mode: navigate` or `Accept: text/html`) are redirected to Keycloak. API requests receive `401 Unauthorized`.

On callback, the raw Keycloak access token is stored as an `HttpOnly` cookie. The cookie `MaxAge` is derived from the JWT `exp` claim. When the token expires, the user is transparently redirected to Keycloak again.

## Configuration

### Required

| Option | JSON key | Description |
|--------|----------|-------------|
| Keycloak issuer URL | `keycloakIssuerURL` | Base URL of the Keycloak realm, e.g. `https://keycloak.example.com/realms/myrealm`. All OIDC endpoints are derived from this. |
| Client ID | `keycloakClientId` | The Keycloak client ID. Used for the OIDC flow and to verify the `azp`/`aud` claim in every JWT. |
| Session secret | `sessionSecret` | Secret used to HMAC-sign the CSRF state cookie. Use a random string of at least 32 characters. |
| Session secret env | `sessionSecretEnv` | Name of the environment variable that holds the session secret. Takes precedence over `sessionSecret`. |

### Optional

| Option | JSON key | Default | Description |
|--------|----------|---------|-------------|
| Required role | `requiredRole` | _(none)_ | Role the authenticated user must have. Checked in `realm_access.roles` (realm role) and `resource_access[clientId].roles` (client role). Leave empty to only require a valid JWT for the correct client, with no role restriction. |
| Keycloak scopes | `keycloakScopes` | `openid` | Space-separated OAuth2 scopes to request. |
| Token cookie name | `tokenCookieName` | `_kc_token` | Name of the cookie in which the JWT access token is stored. |
| Token cookie secure | `tokenCookieSecure` | `true` | Whether to set the `Secure` flag on the token and state cookies. Set to `false` only in local HTTP development. |
| Callback path | `callbackPath` | `/sso/callback` | Path on the protected host that Keycloak redirects back to after authentication. Must be registered as a valid redirect URI in the Keycloak client. |
| Logout path | `logoutPath` | `/sso/logout` | Path that clears the token cookie and redirects to Keycloak's end-session endpoint. |
| Insecure skip TLS verify | `insecureSkipTLSVerify` | `false` | Disable TLS certificate verification for all requests to Keycloak (token exchange, JWKS fetch). Only for development with self-signed certificates. |

## Usage

### Static configuration (`traefik.yml`)

```yaml
experimental:
  localPlugins:
    keycloak-jwt-auth:
      moduleName: github.com/ndw/keycloak-jwt-auth
```

### Dynamic configuration

```yaml
http:
  middlewares:
    my-keycloak-auth:
      plugin:
        keycloak-jwt-auth:
          keycloakIssuerURL: "https://keycloak.example.com/realms/myrealm"
          keycloakClientId: "my-app"
          requiredRole: "user"
          sessionSecretEnv: "SESSION_SECRET"
          callbackPath: "/sso/callback"
          logoutPath: "/sso/logout"

  routers:
    my-router:
      rule: "Host(`app.example.com`)"
      middlewares:
        - my-keycloak-auth
      service: my-service
```

### Docker Compose (local plugin)

```yaml
services:
  traefik:
    image: traefik:v3
    volumes:
      - ./traefik/plugins-local:/plugins-local
    environment:
      - SESSION_SECRET=your-32-char-random-secret-here
    labels:
      - "traefik.http.middlewares.my-auth.plugin.keycloak-jwt-auth.keycloakIssuerURL=https://keycloak.example.com/realms/myrealm"
      - "traefik.http.middlewares.my-auth.plugin.keycloak-jwt-auth.keycloakClientId=my-app"
      - "traefik.http.middlewares.my-auth.plugin.keycloak-jwt-auth.requiredRole=user"
      - "traefik.http.middlewares.my-auth.plugin.keycloak-jwt-auth.sessionSecretEnv=SESSION_SECRET"
```

## Token validation details

The access token cookie is set `HttpOnly; SameSite=Lax` to prevent XSS and CSRF access. The JWT is verified on every request — the cookie value is never trusted without signature verification.

**ClientId check** — the plugin looks for `keycloakClientId` in:
- `azp` (authorized party) — set by Keycloak for access tokens issued to a single confidential client
- `aud` (audience) — may be a single string or a JSON array

**Role check** (`requiredRole`) — the plugin accepts the role if it appears in either:
- `realm_access.roles` — realm-level roles
- `resource_access[keycloakClientId].roles` — client-level roles

**Supported JWT algorithms:** `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`.

**JWKS caching** — public keys are cached in memory keyed by `kid`. On a cache miss the JWKS endpoint is fetched and the entire cache is replaced, which handles Keycloak key rotation automatically. To prevent a flood of requests carrying tokens from a foreign issuer from hammering Keycloak, fetches are rate-limited to at most one per second — unknown kids that arrive within that window are rejected immediately without a network call. Transient errors (network failures, 5xx responses) are retried up to three times with a 500 ms pause between attempts before the request is failed.

## Keycloak client setup

1. Create a client and leave **Client authentication** disabled (public client — no secret required).
2. Set **Valid redirect URIs** to include the callback path, e.g. `https://app.example.com/sso/callback`.
3. Set **Valid post-logout redirect URIs** to `https://app.example.com/*` (or the specific root URL).

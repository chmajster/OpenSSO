# OIDC and OAuth integration

## Metadata

OpenID Provider Discovery:

```text
/.well-known/openid-configuration
```

OAuth Authorization Server Metadata:

```text
/.well-known/oauth-authorization-server
```

JWKS:

```text
/.well-known/jwks.json
```

The issuer is exactly `OPENSSO_PUBLIC_URL`.

## Supported grants

- Authorization Code with mandatory PKCE S256;
- Refresh Token with rotation and reuse detection;
- Client Credentials for confidential clients.

Implicit and Resource Owner Password grants are not implemented.

## Supported scopes

- `openid`
- `profile`
- `email`
- `groups`

Application registration controls the allowed scopes per client.

## Authorization Code + PKCE

Authorization request:

```text
GET /oauth2/authorize
  ?response_type=code
  &client_id=<client_id>
  &redirect_uri=<exact_registered_uri>
  &scope=openid%20profile%20email
  &state=<random_state>
  &nonce=<random_nonce>
  &code_challenge=<base64url_sha256_verifier>
  &code_challenge_method=S256
```

The verifier must meet RFC 7636 character and length constraints. Only S256 is accepted.

When the browser has no OpenSSO session, the user is redirected through the SPA login and then returned to the authorization request. If the user has not already granted all requested scopes, a consent screen is shown.

The resulting authorization code is short-lived and single-use.

Token exchange:

```text
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
client_id=<public_client_id>
code=<authorization_code>
redirect_uri=<same_exact_uri>
code_verifier=<original_verifier>
```

Confidential clients authenticate with HTTP Basic or `client_secret_post`.

## Token response

Successful user authorization returns:
- `access_token`
- `token_type=Bearer`
- `expires_in`
- `scope`
- `id_token` when `openid` is present
- `refresh_token`

Access and ID tokens are RS256 JWTs and carry the registered client ID in `aud`.

## ID token claims

Base claims:
- `iss`
- `sub`
- `aud`
- `iat`
- `exp`
- `nonce` when supplied by the authorization request

`profile` adds:
- `name`
- `preferred_username`

`email` adds:
- `email`
- `email_verified`

`groups` adds:
- `groups`

## UserInfo

```text
GET /userinfo
Authorization: Bearer <access_token>
```

UserInfo validates JWT signature/issuer/expiry and checks durable access-token state, revocation and current user activation before returning claims.

## Refresh tokens

```text
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
client_id=<client_id>
refresh_token=<refresh_token>
```

Each successful refresh consumes the presented token and issues a successor. Reuse of a consumed/revoked token revokes every token in that refresh family.

## Client Credentials

Confidential client example:

```bash
curl -u 'CLIENT_ID:CLIENT_SECRET' \
  -X POST https://sso.example.com/oauth2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=client_credentials' \
  --data-urlencode 'scope=profile'
```

The `openid` scope is rejected for Client Credentials because there is no end-user subject.

## Introspection

```text
POST /oauth2/introspect
```

Introspection requires a confidential authenticated client and returns `active=false` for invalid, expired or revoked tokens.

## Revocation

```text
POST /oauth2/revoke
```

A matching refresh token revokes its entire token family. A matching access token records revocation against its JTI. Revocation intentionally returns success even when the provided token is not active.

## Logout

```text
GET|POST /oauth2/logout
```

When `post_logout_redirect_uri` is supplied, `id_token_hint` is required. OpenSSO extracts the client audience and permits only an exact registered post-logout redirect URI. Optional `state` is returned to the relying party.

## Client-secret lifecycle

Confidential client secrets are returned only:
- at initial client creation;
- after explicit rotation.

The API never returns the stored secret later. Integrations must persist the one-time value securely.

## Application assignments and User Portal

Applications can be assigned directly to users or to groups. User Portal resolves both assignment types. An application with `initiate_login_uri` exposes a launch action to the assigned user.

Assignments control User Portal visibility; they do not replace the OIDC authorization/consent checks.

## Rate limiting

The token endpoint uses Redis-backed rate limiting. Local login is separately rate-limited.

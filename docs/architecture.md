# OpenSSO architecture

## Status

OpenSSO is implemented as a self-hosted Identity Provider and IAM modular monolith. The current production-capable slice contains local identity administration, RBAC, User Portal and an OIDC/OAuth provider with Authorization Code + PKCE, Client Credentials, refresh rotation, introspection, revocation and logout.

## Components

```text
Browser / relying party / OAuth client
                 |
                 v
        +-------------------+
        | nginx + React SPA |
        +---------+---------+
                  |
                  v
        +-------------------+
        | OpenSSO Go API    |
        | modular monolith  |
        +----+---------+----+
             |         |
             v         v
        PostgreSQL   Redis
        durable      distributed
        state        ephemeral state
```

The frontend and protocol endpoints are exposed through one external origin. nginx serves the SPA and proxies API/protocol traffic to the Go service.

## Domain boundaries

- auth: local password verification, bootstrap, login throttling and authenticated browser principals;
- users: identity lifecycle, profile and password state;
- groups: groups and membership;
- rbac: built-in roles, permissions and authorization decisions;
- applications: OIDC client registrations, redirect URIs, launch URIs and user/group assignments;
- sessions: browser-session creation, inspection and revocation;
- oidc/oauth: discovery, consent, authorization code, token issuance, userinfo, refresh rotation, introspection, revocation and logout;
- keys: encrypted RS256 signing-key lifecycle and JWKS publication;
- audit: security and administrative events;
- database: PostgreSQL pool and versioned transactional migrations;
- observability: structured logs, request IDs and health/readiness.

Backend authorization is enforced at handler/service boundaries. Frontend navigation is permission-aware but is not a security boundary.

## Durable data model

Identity:
- `users`
- `password_credentials`
- `groups`
- `group_memberships`
- `roles`
- `permissions`
- `role_permissions`
- `role_assignments`

Applications:
- `applications`
- `oauth_clients`
- `oauth_redirect_uris`
- `oauth_post_logout_redirect_uris`
- `application_user_assignments`
- `application_group_assignments`

Browser/authentication:
- `sessions`
- `security_policies`

OIDC/OAuth:
- `oauth_consents`
- `oauth_authorization_requests`
- `authorization_codes`
- `refresh_tokens`
- `oauth_access_tokens`
- `signing_keys`

Operations:
- `audit_events`
- `schema_migrations`
- `system_state`

## Secret-storage model

Values that never need recovery are stored as verifiers/hashes:
- passwords: Argon2id hashes with per-password salts;
- browser session tokens: SHA-256 hashes;
- client secrets: SHA-256 hashes;
- authorization codes/request tokens: SHA-256 hashes;
- refresh tokens: SHA-256 hashes.

Signing private keys must be recoverable to issue tokens, so they are encrypted with AES-GCM using the deployment `OPENSSO_MASTER_KEY`. Public JWK material remains plaintext.

## Browser-session model

Authentication creates an opaque random session ID and CSRF token. The session ID cookie is HttpOnly; only its hash is stored in PostgreSQL. Sessions have absolute expiry controlled by the security policy and can be revoked by user, administrator, user-wide or globally.

## OIDC Authorization Code + PKCE

1. The relying party sends `response_type=code`, registered `client_id`, exact `redirect_uri`, `state`, requested scopes and a PKCE S256 challenge to `/oauth2/authorize`.
2. OpenSSO validates the client, exact redirect URI, scopes and PKCE method.
3. An unauthenticated user is redirected to the SPA login while preserving the authorization request.
4. Existing consent is reused only when it covers all requested scopes; otherwise OpenSSO presents a CSRF-protected consent screen.
5. Approval creates a short-lived authorization code. Only the code hash is stored.
6. `/oauth2/token` atomically consumes the code and validates client, redirect URI and code verifier.
7. OpenSSO issues an RS256 access token, an ID token for `openid`, and a rotating refresh token.
8. Reusing a consumed refresh token revokes the whole refresh family.
9. `/userinfo`, introspection and revocation check durable token state.
10. RP-initiated logout validates the registered post-logout redirect URI using the ID-token audience.

## Client Credentials

Confidential clients can use `client_credentials` with an allowed non-`openid` scope. Public clients cannot use this grant.

## Signing-key model

A signing key is generated at startup if none exists. RS256 private keys use 3072-bit RSA and are encrypted with AES-GCM. Each key has a random `kid`. Rotation retires the previous active key but retains its public JWK so already-issued tokens remain verifiable.

## Security model

- default-deny backend RBAC;
- exact redirect and post-logout URI matching;
- PKCE S256;
- fixed RS256 JWT verification;
- CSRF protection on cookie-authenticated mutations and consent;
- Host-header validation against the canonical issuer;
- distributed Redis rate limiting;
- account lockout;
- strict request-size/JSON validation;
- security response headers;
- no password/token/client-secret/private-key logging;
- parameterized database statements;
- immutable-style audit trail.

## Threat model

Primary threats include credential stuffing, brute force, session fixation, CSRF, authorization-code replay, redirect bypass, PKCE downgrade, JWT algorithm confusion, stolen refresh tokens, refresh reuse, privilege escalation/IDOR, secret leakage, SQL injection and bootstrap takeover.

Controls are mapped directly to these threats: Argon2id, Redis throttling, opaque hashed sessions, CSRF, strict redirect validation, single-use codes, PKCE S256, fixed signing algorithms, encrypted signing keys, refresh-family revocation, backend RBAC, parameterized SQL and one-time transactional bootstrap.

## Horizontal scaling

API instances are stateless apart from shared PostgreSQL and Redis.

PostgreSQL contains sessions, authorization requests/codes, client state, refresh-token families, access-token JTIs, signing keys and IAM data. Redis contains distributed rate-limit counters. All API replicas must share the same PostgreSQL, Redis, `OPENSSO_MASTER_KEY` and `OPENSSO_PUBLIC_URL`.

## Migration strategy

Migrations are numbered SQL files embedded in the API binary. The migration runner creates one PostgreSQL transaction per unapplied migration and records the migration version only after the transaction succeeds. Startup fails on migration errors.

## Deployment

`docker compose up -d --build` starts frontend, API, PostgreSQL and Redis. No default administrator exists. A fresh installation remains in bootstrap state until the first administrator is created.

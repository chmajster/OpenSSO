# OpenSSO architecture

## Status
Initial architecture for the first implementation slice. The repository starts from AGENTS.md only, so this document establishes the system boundaries before code is added.

## Goals
OpenSSO is a self-hosted Identity Provider and IAM platform. The first production-capable slice covers bootstrap, local authentication, users, groups, RBAC, sessions, audit, application registration, health/observability primitives and the OIDC authorization-code flow with PKCE.

## Components

```text
Browser / relying party
        |
        v
+---------------------------+
| OpenSSO HTTP application  |
| Go modular monolith       |
+-------------+-------------+
              |
      +-------+--------+
      |                |
      v                v
 PostgreSQL           Redis
 durable state    distributed ephemeral state
```

The React/TypeScript admin UI is a separate source tree built into static assets and served by the same deployment. Protocol endpoints are kept separate from `/api/v1` administrative endpoints.

## Domain boundaries
- auth: password verification, login throttling, bootstrap and authenticated principal creation.
- users: lifecycle of local users.
- groups: groups and membership.
- rbac: roles, permissions and authorization decisions.
- applications: OIDC/OAuth client registrations.
- sessions: browser sessions and revocation.
- oidc/oauth: discovery, authorization, token issuance, userinfo, revocation and JWKS.
- audit: immutable security and administrative events.
- keys: signing-key lifecycle and JWKS publication.
- database: PostgreSQL connection and migrations.
- observability: health, request IDs, structured logs and metrics hooks.

Domain packages must not depend on HTTP handlers. Handlers call application services; services own transaction boundaries and authorization checks.

## Data model
Core tables are users, password_credentials, groups, group_memberships, roles, permissions, role_assignments, applications, oauth_clients, oauth_redirect_uris, authorization_codes, sessions, refresh_tokens, audit_events and signing_keys.

Security-critical one-time values are stored as hashes where recovery of the original value is unnecessary. Passwords use Argon2id. Client secrets are displayed once and stored as verifiers. Refresh tokens are rotated and represented by non-reversible hashes.

## Session model
Browser sessions use an opaque random cookie value. Only a hash is stored server-side. Authentication rotates the session identifier. Cookies are HttpOnly, Secure in production, SameSite=Lax, and scoped narrowly. Absolute and idle expiry are enforced by the backend.

## OIDC authorization-code flow
1. Client calls `/oauth2/authorize` with an exact registered redirect URI, state, nonce and PKCE challenge.
2. OpenSSO validates client policy and authenticated browser session.
3. A single-use short-lived authorization code is issued and persisted as a hash.
4. Client exchanges the code at `/oauth2/token`.
5. The backend atomically consumes the code and validates PKCE.
6. OpenSSO returns signed ID/access tokens and, where allowed, a refresh token.
7. Refresh rotation revokes the predecessor and detects reuse.
8. `/userinfo`, introspection and revocation enforce token/client semantics.
9. Signing public keys are exposed through JWKS.

## Signing keys
The initial compatibility algorithm is RS256. Private key material is encrypted at rest using an application master key supplied from deployment configuration. Each public key has a `kid`. Rotated public keys remain published until all tokens signed by them have expired.

## Security model
- Default deny authorization.
- RBAC enforced in backend services and handlers.
- Exact redirect URI matching; wildcard redirects are rejected.
- CSRF protection for cookie-authenticated state-changing administrative operations.
- Strict input size limits, request timeouts and normalized validation errors.
- No passwords, bearer tokens, refresh tokens, client secrets or private keys in logs or audit metadata.
- Redis-backed rate limiting is used for horizontally scaled login/token/MFA paths.
- Security headers include CSP, frame denial, nosniff and a restrictive referrer policy.
- CORS is disabled by default for administrative APIs and explicitly configured where needed.

## Threat model
Primary threats are credential stuffing, brute force, session fixation, stolen refresh tokens, redirect URI bypass, authorization-code replay, JWT algorithm confusion, privilege escalation/IDOR, CSRF, XSS, SQL injection, SSRF through directory/federation configuration, secret leakage and bootstrap takeover.

Mitigations include Argon2id, distributed rate limiting, opaque hashed sessions, one-use codes, PKCE S256, strict redirect validation, fixed signing algorithms, backend RBAC, parameterized SQL, encrypted reversible secrets, one-time bootstrap state and security regression tests.

## Horizontal scaling
HTTP instances are stateless apart from PostgreSQL and Redis. PostgreSQL stores durable identity, policy, client, token-family and audit state. Redis stores distributed rate-limit counters and other explicitly ephemeral coordination. Signing keys are durable shared state, so all instances publish and use the same active key set.

## Migration strategy
Migrations are versioned SQL files executed by an explicit migration command before application readiness. The application does not silently mutate schema after startup. Migrations are transactional where PostgreSQL permits it.

## Deployment
`docker compose up -d` starts OpenSSO, PostgreSQL and Redis. Secrets are injected through environment variables or mounted secret files. No fixed administrator credentials are provided. A fresh installation enters a one-time bootstrap flow and permanently disables it after the first administrator is created.

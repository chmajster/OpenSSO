# Security

## Authentication

Local passwords are hashed with Argon2id using a random salt per password. Verification uses constant-time comparison. The configured minimum length is enforced by the backend. Accounts created by an administrator and accounts receiving an administrative password reset are marked `must_change_password` and cannot use administrative capabilities until the user changes the password.

Login attempts are throttled through Redis so limits are shared by horizontally scaled HTTP instances. Repeated failures increment account counters and can create a temporary lock according to the security policy.

## Browser sessions and CSRF

Browser sessions use cryptographically random opaque identifiers. PostgreSQL stores only SHA-256 hashes of those identifiers. Cookies are HttpOnly for the session identifier, SameSite=Lax, and Secure when `OPENSSO_COOKIE_SECURE=true`.

State-changing `/api/v1` requests use a double-submit CSRF token. Consent uses its own CSRF field validation. Host-header validation is anchored to `OPENSSO_PUBLIC_URL`.

Administrators can revoke one session, all sessions for one user, or all active sessions. Users can inspect and revoke their own sessions.

## Authorization

Authorization is backend-enforced RBAC; hiding a UI element is never treated as a security boundary. Default administrative access is deny-unless-permitted.

Built-in roles:
- Super Admin
- Admin
- User Administrator
- Application Administrator
- Security Administrator
- Read Only Administrator
- User

The initial administrator is assigned Super Admin. Administrator-created users receive the User role by default.

## Bootstrap

There are no fixed administrator credentials. A fresh installation requires a high-entropy deployment bootstrap token and a transactionally protected uninitialized database state. Once the first administrator transaction commits, bootstrap cannot be replayed even if the environment token remains configured. The deployment token should still be removed immediately after initialization.

## OIDC/OAuth client security

Redirect URIs and post-logout redirect URIs are matched exactly. Wildcards are rejected. Authorization Code clients require PKCE S256.

Public clients do not receive a client secret. Confidential secrets are generated from cryptographic randomness, returned only at creation or rotation, and stored only as SHA-256 verifiers.

Authorization codes are short-lived, single-use and stored as hashes. Code exchange verifies the exact client, redirect URI and PKCE verifier.

## Tokens

Access and ID tokens are signed with RS256 and include a `kid`. The server accepts only RS256 when validating its own tokens, preventing algorithm confusion.

Private signing keys are encrypted at rest with AES-GCM using `OPENSSO_MASTER_KEY`, a required base64-encoded 32-byte deployment key. Public keys are published through JWKS. Retired public keys remain available for validation while they exist in the key table.

Refresh tokens are opaque random values stored as hashes. Each token belongs to a family. Successful use consumes the current token and issues a successor. Reuse of a consumed or revoked token revokes the entire family and creates an audit event.

Revoked access-token JTIs and active state are stored in PostgreSQL so introspection and userinfo can enforce revocation in addition to JWT signature/expiry validation.

## Consent and claims

Consent is stored per user/application with granted scopes. Supported scopes are `openid`, `profile`, `email` and `groups`. Group claims are derived from current group membership.

## Rate limiting

Redis-backed counters protect local login and OAuth token issuance. If Redis is unavailable, readiness fails; token/login throttling does not silently fall back to process-local counters.

## Input and browser hardening

The HTTP layer applies:
- request-body size limits;
- strict JSON decoding with unknown-field rejection;
- request/header/idle timeouts;
- request IDs;
- Content-Security-Policy;
- frame denial;
- `nosniff`;
- restrictive referrer policy.

Database statements are parameterized. Secrets are excluded from audit metadata and normal logs.

## Audit

Authentication and administrative mutations record actor, target, event, result, source IP, user agent and request ID. Passwords, bearer tokens, refresh tokens, client secrets and private signing keys are not audit fields.

## Threat model

Primary threats include credential stuffing, brute force, session fixation, CSRF, redirect URI bypass, authorization-code replay, PKCE downgrade, JWT algorithm confusion, stolen refresh-token reuse, privilege escalation/IDOR, SQL injection, secret leakage and bootstrap takeover.

Implemented mitigations include Argon2id, distributed throttling, account lockout, opaque hashed sessions, CSRF validation, strict host/redirect validation, PKCE S256, single-use codes, fixed JWT algorithms, encrypted signing keys, refresh-family reuse detection, backend RBAC, parameterized SQL, one-time bootstrap state and live E2E security-flow tests.

## Deployment requirements

Production deployments should:
- terminate HTTPS before exposing OpenSSO;
- set `OPENSSO_COOKIE_SECURE=true`;
- set `OPENSSO_PUBLIC_URL` to the canonical HTTPS issuer URL;
- keep PostgreSQL and Redis on private networks;
- protect and back up `OPENSSO_MASTER_KEY` separately from the database;
- remove the bootstrap token after initialization;
- encrypt database backups.

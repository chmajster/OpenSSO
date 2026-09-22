# Security

## Authentication
Local passwords are hashed with Argon2id using per-password random salts. Password verification uses constant-time comparison. Login failures are throttled through Redis so limits are shared between application instances. Repeated failures also trigger a temporary account lock.

## Sessions
Browser sessions use cryptographically random opaque identifiers. Only SHA-256 hashes of those identifiers are stored in PostgreSQL. Cookies are HttpOnly and SameSite=Lax. Production deployments behind HTTPS must set `OPENSSO_COOKIE_SECURE=true`.

## Authorization
Administrative authorization is server-side RBAC. UI visibility is not treated as a security boundary. The initial Super Admin receives all defined permissions through role-permission mappings.

## Bootstrap
There are no fixed administrator credentials. A fresh installation requires a high-entropy deployment bootstrap token and a transactionally protected uninitialized database state. Once initialization commits, the same flow cannot be replayed.

## Client registration
Redirect URIs must be absolute, parseable and exact. Wildcards are rejected. Public clients never receive a secret. Confidential client secrets are returned once and only a hash is stored.

## Audit
Authentication and administrative mutations create audit events with actor, target, result, source IP, user agent and request ID. Secrets are not written into audit metadata.

## Current protocol exposure
OIDC/OAuth, SAML and SCIM protocol endpoints are intentionally absent until each protocol slice meets its complete security and interoperability definition of done. This prevents external applications from treating a partial implementation as a production Identity Provider.

## Deployment
Use HTTPS, set secure cookies, protect PostgreSQL and Redis on private networks, rotate the bootstrap token out of configuration after setup, and keep database backups encrypted.

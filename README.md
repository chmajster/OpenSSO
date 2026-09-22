# OpenSSO

OpenSSO is a self-hosted Identity & Access Management and Single Sign-On platform implemented as a Go modular monolith with PostgreSQL, Redis and a React/TypeScript UI.

## Current capabilities

Identity and administration:
- one-time installation bootstrap with no default administrator credentials;
- local users, activation/deactivation, unlock and administrative password reset;
- forced password change after administrator-created accounts and resets;
- groups with membership management;
- backend-enforced RBAC with Super Admin, Admin, User Administrator, Application Administrator, Security Administrator, Read Only Administrator and User roles;
- security policy for password length, account lockout and browser-session TTL;
- per-user, per-session and global browser-session revocation;
- immutable-style audit events for authentication and administrative mutations;
- permission-aware administration UI with search and pagination;
- self-service User Portal for assigned applications, profile, password and own sessions.

OIDC/OAuth:
- OpenID Provider Discovery;
- OAuth Authorization Server Metadata;
- Authorization Code flow;
- mandatory PKCE S256 for browser authorization;
- consent screen and persisted grants;
- exact redirect URI matching; wildcard redirect URIs are rejected;
- RS256 access and ID tokens;
- JWKS publication and signing-key rotation;
- encrypted private signing keys at rest using the deployment master key;
- `openid`, `profile`, `email` and `groups` scopes;
- `/userinfo`;
- rotating refresh tokens with reuse detection and family revocation;
- Client Credentials grant for confidential clients;
- token introspection and RFC-style revocation behavior;
- RP-initiated logout with exact registered post-logout redirect URI;
- public and confidential client registrations;
- one-time client-secret display and secret rotation;
- user/group assignment to applications and launch URLs for User Portal.

Operational:
- PostgreSQL-backed durable state and versioned transactional migrations;
- Redis-backed distributed authentication/token throttling;
- liveness and dependency-aware readiness endpoints;
- Docker Compose deployment;
- CI for clean `go mod tidy`, `gofmt`, vet, tests, binary builds, `govulncheck`, frontend type/build checks, Compose validation and live end-to-end flows.

## Quick start

Create local configuration:

```bash
cp .env.example .env
```

Generate independent secrets:

```bash
openssl rand -base64 36
openssl rand -base64 36
openssl rand -base64 32
```

Set:
- `POSTGRES_PASSWORD` to a strong database password;
- `OPENSSO_BOOTSTRAP_TOKEN` to a high-entropy first-run token;
- `OPENSSO_MASTER_KEY` to the base64 output of exactly 32 random bytes.

For local HTTP development leave:

```text
OPENSSO_PUBLIC_URL=http://localhost:8080
OPENSSO_COOKIE_SECURE=false
```

Start the stack:

```bash
docker compose up -d --build
```

Open `http://localhost:8080`. A fresh database shows the bootstrap form. Supply `OPENSSO_BOOTSTRAP_TOKEN` and create the first Super Admin.

After successful initialization remove `OPENSSO_BOOTSTRAP_TOKEN` from the runtime environment and restart the API container. Database state permanently prevents a second bootstrap.

Production deployments must use HTTPS and set:

```text
OPENSSO_PUBLIC_URL=https://sso.example.com
OPENSSO_COOKIE_SECURE=true
```

## OIDC integration

Discovery:

```text
https://sso.example.com/.well-known/openid-configuration
```

Core endpoints:
- authorize: `/oauth2/authorize`
- token: `/oauth2/token`
- userinfo: `/userinfo`
- JWKS: `/.well-known/jwks.json`
- revoke: `/oauth2/revoke`
- introspect: `/oauth2/introspect`
- logout: `/oauth2/logout`

Authorization Code clients must use `code_challenge_method=S256`. Redirect URIs and post-logout redirect URIs use exact registration matching.

See `docs/oidc.md` for protocol flows and examples.

## Development

Backend:

```bash
cd backend
go mod tidy
gofmt -w .
go vet ./...
go test ./...
go build ./cmd/opensso
go build ./cmd/healthcheck
```

Frontend:

```bash
cd frontend
npm install --no-audit --no-fund
npm run lint
npm run build
```

Full stack:

```bash
docker compose up -d --build
bash scripts/e2e-foundation.sh
```

The E2E flow covers fresh installation, IAM administration, User Portal, OIDC Authorization Code + PKCE, refresh-token rotation/reuse detection, Client Credentials, introspection, revocation and logout.

## Health

- `GET /health/live`: process liveness.
- `GET /health/ready`: PostgreSQL and Redis readiness.

## Documentation

- `docs/architecture.md`: components, data model and scaling model.
- `docs/security.md`: security controls and threat mitigations.
- `docs/oidc.md`: OIDC/OAuth integration behavior.
- `docs/openapi.yaml`: administrative/self-service HTTP API.
- `docs/deployment.md`: deployment requirements.
- `docs/development.md`: development and verification commands.

# OpenSSO

OpenSSO is a self-hosted Identity & Access Management / Single Sign-On platform. The current implementation establishes the secure foundation required before exposing protocol endpoints such as OIDC, SAML or SCIM.

## Implemented

- Go modular-monolith backend.
- PostgreSQL schema and controlled migrations.
- Redis-backed distributed login throttling.
- One-time first administrator bootstrap.
- Argon2id password hashing.
- Opaque hashed browser sessions with backend authorization.
- Users and groups.
- Backend RBAC with roles and role assignments.
- OIDC application registration with exact redirect URI validation, PKCE requirement and one-time client-secret display.
- Audit trail for authentication and administrative operations.
- React + TypeScript administration UI.
- Liveness and dependency-aware readiness endpoints.
- Docker Compose deployment.
- CI for formatting, vet, tests, builds, vulnerability checks and frontend type/build checks.

Protocol endpoints are deliberately not advertised as working yet. OIDC discovery, authorization, token, JWKS, userinfo, refresh and revocation will be exposed only when the complete flow is implemented and tested end-to-end.

## Start

Create local configuration:

```bash
cp .env.example .env
```

Generate independent secrets, for example:

```bash
openssl rand -base64 36
openssl rand -base64 36
```

Put one value in `POSTGRES_PASSWORD` and the other in `OPENSSO_BOOTSTRAP_TOKEN`.

Start:

```bash
docker compose up -d --build
```

Open `http://localhost:8080`. On a fresh database the UI displays the one-time initialization form. Supply the bootstrap token and create the first Super Admin.

After successful initialization, the bootstrap API refuses a second initialization because the database state is locked transactionally. The deployment bootstrap token should then be removed from the environment and the API container restarted.

## Development

Backend:

```bash
cd backend
go test ./...
go run ./cmd/opensso
```

Frontend:

```bash
cd frontend
npm install
npm run dev
```

The Vite development server proxies `/api` and `/health` to the Go backend on port 8080.

## Health

- `GET /health/live` verifies the process is serving HTTP.
- `GET /health/ready` verifies PostgreSQL and Redis connectivity.

## Security

See `docs/architecture.md` and `docs/security.md`. Do not commit real credentials, bootstrap tokens, database passwords, client secrets or private keys.

# Deployment

The reference deployment is `docker-compose.yml`. It starts:
- React/nginx frontend;
- Go OpenSSO API;
- PostgreSQL;
- Redis.

## Required configuration

`POSTGRES_PASSWORD`  
Strong PostgreSQL password.

`OPENSSO_BOOTSTRAP_TOKEN`  
High-entropy token used only for the first administrator bootstrap. Remove it after successful initialization.

`OPENSSO_MASTER_KEY`  
Base64-encoded 32-byte key used to encrypt OIDC signing private keys at rest. Generate with:

```bash
openssl rand -base64 32
```

This key must remain stable across restarts and replicas. Losing it makes stored encrypted signing private keys unusable. Treat it as a backup-critical secret.

`OPENSSO_PUBLIC_URL`  
Canonical external issuer URL. The host is also used for Host-header validation.

`OPENSSO_COOKIE_SECURE`  
Set to `true` for HTTPS deployments.

Example production values:

```text
OPENSSO_PUBLIC_URL=https://sso.example.com
OPENSSO_COOKIE_SECURE=true
```

## Startup

```bash
docker compose up -d --build
```

The API connects to PostgreSQL and Redis, executes pending versioned migrations, ensures an active encrypted RS256 signing key exists, then becomes ready. Any failure in configuration, migration, database, Redis or signing-key initialization prevents successful startup/readiness.

## Persistence

PostgreSQL stores identities, groups, RBAC, clients, consents, authorization state, token families, access-token JTIs, sessions, audit events and signing keys.

Redis stores distributed rate-limit and ephemeral coordination state.

The reference Compose file uses persistent volumes for PostgreSQL and Redis.

## Health

`/health/live` checks process liveness.

`/health/ready` requires PostgreSQL and Redis connectivity.

## Reverse proxy

The reference nginx container proxies:
- `/api/`
- `/health/`
- `/.well-known/`
- `/oauth2/`
- `/userinfo`

to the Go API and serves the React SPA for other browser routes.

When adding an external load balancer or reverse proxy, preserve the original Host header and ensure it matches `OPENSSO_PUBLIC_URL`.

## Horizontal scaling

Multiple API instances can share PostgreSQL and Redis. Browser sessions, OAuth state, token families and signing keys are durable/shared rather than process-local. Redis rate-limit counters are also shared.

All replicas must receive the same `OPENSSO_MASTER_KEY` and canonical `OPENSSO_PUBLIC_URL`.

## Backup

Back up PostgreSQL and the deployment master key. Protect them independently. A database backup without the corresponding master key cannot restore private signing-key material.

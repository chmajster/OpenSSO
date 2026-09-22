# Development

The backend is a Go modular monolith under `backend/internal`. PostgreSQL stores durable identity/protocol state and Redis stores distributed throttling state. The frontend is React + TypeScript built with Vite.

## Backend checks

```bash
cd backend
go mod tidy
git diff --exit-code
gofmt -w .
git diff --exit-code
go vet ./...
go test ./...
go build ./cmd/opensso
go build ./cmd/healthcheck
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...
```

`go.mod`, `go.sum` and formatted Go sources are committed. CI fails if `go mod tidy` or `gofmt` changes the checkout.

## Frontend checks

```bash
cd frontend
npm install --no-audit --no-fund
npm run lint
npm run build
```

## Live stack verification

Configure the same environment required by Compose, then:

```bash
docker compose up -d --build
bash scripts/e2e-foundation.sh
```

The E2E script starts from a fresh database and exercises:
- bootstrap;
- local login and CSRF;
- user/group/RBAC administration;
- application registration, assignments and client-secret rotation;
- forced first-login password change and User Portal;
- Discovery and JWKS;
- OIDC Authorization Code + PKCE + consent;
- code replay rejection;
- userinfo;
- refresh-token rotation and reuse-family revocation;
- Client Credentials;
- introspection and revocation;
- RP-initiated logout.

## Change discipline

Do not expose a protocol endpoint until its complete supported flow is implemented and tested. Security enforcement belongs in backend handlers/services, not only in the frontend.

Every schema change is a new numbered migration. Existing applied migration behavior must remain deterministic.

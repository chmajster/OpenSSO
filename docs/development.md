# Development

The backend uses Go packages under `backend/internal`. HTTP handlers own transport concerns; durable state is PostgreSQL and distributed throttling uses Redis.

Run backend checks with:

```bash
cd backend
gofmt -w .
go vet ./...
go test ./...
go build ./cmd/opensso
```

Run frontend checks with:

```bash
cd frontend
npm install --no-audit --no-fund
npm run lint
npm run build
```

Do not add UI routes for protocol features until the corresponding backend flow is complete and tested.

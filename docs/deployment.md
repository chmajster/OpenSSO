# Deployment

The reference deployment is `docker-compose.yml`. It starts the React/nginx frontend, Go API, PostgreSQL and Redis.

Required secrets:
- `POSTGRES_PASSWORD`
- `OPENSSO_BOOTSTRAP_TOKEN` for first initialization only

For HTTPS deployments set:
- `OPENSSO_PUBLIC_URL=https://sso.example.com`
- `OPENSSO_COOKIE_SECURE=true`

Readiness depends on live PostgreSQL and Redis connectivity. Persistent volumes store PostgreSQL and Redis data. Database migrations are executed by the API before it begins serving normal traffic; migration failure stops startup.

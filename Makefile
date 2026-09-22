.PHONY: up down test backend-test frontend-test

up:
	docker compose up -d --build

down:
	docker compose down

test: backend-test frontend-test

backend-test:
	cd backend && go test ./...

frontend-test:
	cd frontend && npm install --no-audit --no-fund && npm run lint && npm run build

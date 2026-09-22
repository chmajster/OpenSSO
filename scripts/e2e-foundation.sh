#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${OPENSSO_E2E_URL:-http://127.0.0.1:8080}"
BOOTSTRAP_TOKEN="${OPENSSO_BOOTSTRAP_TOKEN:?OPENSSO_BOOTSTRAP_TOKEN is required}"
COOKIE_JAR="$(mktemp)"
trap 'rm -f "$COOKIE_JAR"' EXIT

for _ in $(seq 1 60); do
  if curl -fsS "$BASE_URL/health/ready" >/dev/null; then
    break
  fi
  sleep 2
done
curl -fsS "$BASE_URL/health/ready" >/dev/null

curl -fsS -X POST "$BASE_URL/api/v1/setup/bootstrap"   -H "Authorization: Bearer $BOOTSTRAP_TOKEN"   -H "Content-Type: application/json"   --data '{"username":"e2e-admin","email":"e2e-admin@example.test","display_name":"E2E Admin","password":"e2e-initial-password-123"}' >/dev/null

curl -fsS -c "$COOKIE_JAR" -X POST "$BASE_URL/api/v1/auth/login"   -H "Content-Type: application/json"   --data '{"username":"e2e-admin","password":"e2e-initial-password-123"}' >/dev/null

CSRF="$(awk '$6=="opensso_csrf"{print $7}' "$COOKIE_JAR" | tail -n1)"
test -n "$CSRF"

api_mutate() {
  local method="$1"; shift
  local path="$1"; shift
  curl -fsS -b "$COOKIE_JAR" -c "$COOKIE_JAR" -X "$method" "$BASE_URL$path"     -H "Content-Type: application/json"     -H "X-CSRF-Token: $CSRF" "$@"
}

USER_JSON="$(api_mutate POST /api/v1/users --data '{"username":"e2e-user","email":"e2e-user@example.test","display_name":"E2E User","password":"temporary-user-password-123"}')"
USER_ID="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' <<<"$USER_JSON")"

GROUP_JSON="$(api_mutate POST /api/v1/groups --data '{"name":"E2E Group","description":"Integration test group"}')"
GROUP_ID="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' <<<"$GROUP_JSON")"
api_mutate POST "/api/v1/groups/$GROUP_ID/members" --data "{"user_id":"$USER_ID"}" >/dev/null

ROLES_JSON="$(curl -fsS -b "$COOKIE_JAR" "$BASE_URL/api/v1/roles")"
USER_ROLE_ID="$(python3 -c 'import json,sys; d=json.load(sys.stdin); print(next(x["id"] for x in d["items"] if x["name"]=="User"))' <<<"$ROLES_JSON")"
api_mutate POST "/api/v1/users/$USER_ID/roles" --data "{"role_id":"$USER_ROLE_ID"}" >/dev/null

api_mutate POST /api/v1/applications --data '{"name":"E2E OIDC Client","public_client":true,"redirect_uris":["https://client.example.test/callback"]}' >/dev/null

curl -fsS -b "$COOKIE_JAR" "$BASE_URL/api/v1/dashboard" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["users"] >= 2; assert d["applications"] >= 1'
curl -fsS -b "$COOKIE_JAR" "$BASE_URL/api/v1/sessions" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert len(d["items"]) >= 1'
curl -fsS -b "$COOKIE_JAR" "$BASE_URL/api/v1/audit" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert any(x["event"]=="USER_CREATED" for x in d["items"])'

api_mutate POST "/api/v1/users/$USER_ID/unlock" >/dev/null
api_mutate POST "/api/v1/users/$USER_ID/sessions/revoke-all" >/dev/null

POLICY="$(curl -fsS -b "$COOKIE_JAR" "$BASE_URL/api/v1/security/policy")"
python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["password_min_length"] >= 12' <<<"$POLICY"

echo "OpenSSO E2E foundation flow passed."

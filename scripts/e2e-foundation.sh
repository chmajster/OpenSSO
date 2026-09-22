#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${OPENSSO_E2E_URL:-http://127.0.0.1:8080}"
BOOTSTRAP_TOKEN="${OPENSSO_BOOTSTRAP_TOKEN:?OPENSSO_BOOTSTRAP_TOKEN is required}"
COOKIE_JAR="$(mktemp)"
HEADERS_FILE="$(mktemp)"
trap 'rm -f "$COOKIE_JAR" "$HEADERS_FILE"' EXIT

json_field() {
  local field="$1"
  python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$field"
}

for _ in $(seq 1 60); do
  if curl -fsS "$BASE_URL/health/ready" >/dev/null; then
    break
  fi
  sleep 2
done
curl -fsS "$BASE_URL/health/ready" >/dev/null

curl -fsS -X POST "$BASE_URL/api/v1/setup/bootstrap" \
  -H "Authorization: Bearer $BOOTSTRAP_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"username":"e2e-admin","email":"e2e-admin@example.test","display_name":"E2E Admin","password":"e2e-initial-password-123"}' >/dev/null

curl -fsS -c "$COOKIE_JAR" -X POST "$BASE_URL/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  --data '{"username":"e2e-admin","password":"e2e-initial-password-123"}' >/dev/null

CSRF="$(awk '$6=="opensso_csrf"{print $7}' "$COOKIE_JAR" | tail -n1)"
test -n "$CSRF"

api_mutate() {
  local method="$1"; shift
  local path="$1"; shift
  curl -fsS -b "$COOKIE_JAR" -c "$COOKIE_JAR" -X "$method" "$BASE_URL$path" \
    -H "Content-Type: application/json" \
    -H "X-CSRF-Token: $CSRF" "$@"
}

USER_JSON="$(api_mutate POST /api/v1/users --data '{"username":"e2e-user","email":"e2e-user@example.test","display_name":"E2E User","password":"temporary-user-password-123"}')"
USER_ID="$(printf '%s' "$USER_JSON" | json_field id)"

GROUP_JSON="$(api_mutate POST /api/v1/groups --data '{"name":"E2E Group","description":"Integration test group"}')"
GROUP_ID="$(printf '%s' "$GROUP_JSON" | json_field id)"
api_mutate POST "/api/v1/groups/$GROUP_ID/members" --data "{\"user_id\":\"$USER_ID\"}" >/dev/null

ROLES_JSON="$(curl -fsS -b "$COOKIE_JAR" "$BASE_URL/api/v1/roles")"
USER_ROLE_ID="$(python3 -c 'import json,sys; d=json.load(sys.stdin); print(next(x["id"] for x in d["items"] if x["name"]=="User"))' <<<"$ROLES_JSON")"
api_mutate POST "/api/v1/users/$USER_ID/roles" --data "{\"role_id\":\"$USER_ROLE_ID\"}" >/dev/null

APP_JSON="$(api_mutate POST /api/v1/applications --data '{"name":"E2E OIDC Client","public_client":true,"redirect_uris":["https://client.example.test/callback"],"post_logout_redirect_uris":["https://client.example.test/logout"],"allowed_scopes":["openid","profile","email","groups"]}')"
APP_ID="$(printf '%s' "$APP_JSON" | json_field id)"
CLIENT_ID="$(printf '%s' "$APP_JSON" | json_field client_id)"

M2M_JSON="$(api_mutate POST /api/v1/applications --data '{"name":"E2E M2M Client","public_client":false,"redirect_uris":["https://machine.example.test/callback"],"allowed_scopes":["openid","profile"]}')"
M2M_CLIENT_ID="$(printf '%s' "$M2M_JSON" | json_field client_id)"
M2M_SECRET="$(printf '%s' "$M2M_JSON" | json_field client_secret)"
test -n "$M2M_SECRET"

curl -fsS -b "$COOKIE_JAR" "$BASE_URL/api/v1/applications/$APP_ID/integration" |
  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["client_id"]; assert d["issuer"].startswith("http"); assert d["client_secret_retrievable"] is False'

curl -fsS -b "$COOKIE_JAR" "$BASE_URL/api/v1/dashboard" |
  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["users"] >= 2; assert d["applications"] >= 2'
curl -fsS -b "$COOKIE_JAR" "$BASE_URL/api/v1/sessions" |
  python3 -c 'import json,sys; d=json.load(sys.stdin); assert len(d["items"]) >= 1'
curl -fsS -b "$COOKIE_JAR" "$BASE_URL/api/v1/audit" |
  python3 -c 'import json,sys; d=json.load(sys.stdin); assert any(x["event"]=="USER_CREATED" for x in d["items"])'

api_mutate POST "/api/v1/users/$USER_ID/unlock" >/dev/null
api_mutate POST "/api/v1/users/$USER_ID/sessions/revoke-all" >/dev/null

POLICY="$(curl -fsS -b "$COOKIE_JAR" "$BASE_URL/api/v1/security/policy")"
python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["password_min_length"] >= 12; assert d["lockout_threshold"] >= 3' <<<"$POLICY"

curl -fsS "$BASE_URL/.well-known/openid-configuration" |
  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["issuer"]; assert d["authorization_endpoint"].endswith("/oauth2/authorize"); assert "S256" in d["code_challenge_methods_supported"]'
curl -fsS "$BASE_URL/.well-known/oauth-authorization-server" |
  python3 -c 'import json,sys; d=json.load(sys.stdin); assert "authorization_code" in d["grant_types_supported"]'
curl -fsS "$BASE_URL/.well-known/jwks.json" |
  python3 -c 'import json,sys; d=json.load(sys.stdin); assert len(d["keys"]) >= 1; assert d["keys"][0]["alg"]=="RS256"; assert d["keys"][0]["kty"]=="RSA"'

VERIFIER='dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
CHALLENGE='E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
REDIRECT_URI='https://client.example.test/callback'
STATE='e2e-state-123'
NONCE='e2e-nonce-123'

CONSENT_HTML="$(curl -fsS -b "$COOKIE_JAR" -G "$BASE_URL/oauth2/authorize" \
  --data-urlencode "response_type=code" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "redirect_uri=$REDIRECT_URI" \
  --data-urlencode "scope=openid profile email groups" \
  --data-urlencode "state=$STATE" \
  --data-urlencode "nonce=$NONCE" \
  --data-urlencode "code_challenge=$CHALLENGE" \
  --data-urlencode "code_challenge_method=S256")"

REQUEST_TOKEN="$(python3 -c 'import re,sys,html; m=re.search(r"name=\"request_token\" value=\"([^\"]+)\"",sys.stdin.read()); assert m; print(html.unescape(m.group(1)))' <<<"$CONSENT_HTML")"
test -n "$REQUEST_TOKEN"

: >"$HEADERS_FILE"
curl -sS -o /dev/null -D "$HEADERS_FILE" -b "$COOKIE_JAR" -X POST "$BASE_URL/oauth2/authorize/consent" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "request_token=$REQUEST_TOKEN" \
  --data-urlencode "csrf=$CSRF" \
  --data-urlencode "action=approve"

LOCATION="$(awk 'BEGIN{IGNORECASE=1} /^location:/{sub(/^[^:]+:[[:space:]]*/,""); sub(/\r$/,""); print; exit}' "$HEADERS_FILE")"
test -n "$LOCATION"
CODE="$(python3 -c 'import sys,urllib.parse; print(urllib.parse.parse_qs(urllib.parse.urlparse(sys.argv[1]).query)["code"][0])' "$LOCATION")"
RETURNED_STATE="$(python3 -c 'import sys,urllib.parse; print(urllib.parse.parse_qs(urllib.parse.urlparse(sys.argv[1]).query)["state"][0])' "$LOCATION")"
test "$RETURNED_STATE" = "$STATE"

TOKEN_JSON="$(curl -fsS -X POST "$BASE_URL/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "code=$CODE" \
  --data-urlencode "redirect_uri=$REDIRECT_URI" \
  --data-urlencode "code_verifier=$VERIFIER")"
ACCESS_TOKEN="$(printf '%s' "$TOKEN_JSON" | json_field access_token)"
ID_TOKEN="$(printf '%s' "$TOKEN_JSON" | json_field id_token)"
REFRESH_TOKEN="$(printf '%s' "$TOKEN_JSON" | json_field refresh_token)"
test -n "$ACCESS_TOKEN"
test -n "$ID_TOKEN"
test -n "$REFRESH_TOKEN"

curl -fsS "$BASE_URL/userinfo" -H "Authorization: Bearer $ACCESS_TOKEN" |
  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["preferred_username"]=="e2e-admin"; assert d["email"]=="e2e-admin@example.test"'

REPLAY_JSON="$(curl -sS -X POST "$BASE_URL/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "code=$CODE" \
  --data-urlencode "redirect_uri=$REDIRECT_URI" \
  --data-urlencode "code_verifier=$VERIFIER")"
python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["error"]=="invalid_grant"' <<<"$REPLAY_JSON"

REFRESH_JSON="$(curl -fsS -X POST "$BASE_URL/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=refresh_token" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "refresh_token=$REFRESH_TOKEN")"
NEW_REFRESH_TOKEN="$(printf '%s' "$REFRESH_JSON" | json_field refresh_token)"
test "$NEW_REFRESH_TOKEN" != "$REFRESH_TOKEN"

REUSE_JSON="$(curl -sS -X POST "$BASE_URL/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=refresh_token" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "refresh_token=$REFRESH_TOKEN")"
python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["error"]=="invalid_grant"' <<<"$REUSE_JSON"

FAMILY_REVOKED_JSON="$(curl -sS -X POST "$BASE_URL/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=refresh_token" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "refresh_token=$NEW_REFRESH_TOKEN")"
python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["error"]=="invalid_grant"' <<<"$FAMILY_REVOKED_JSON"

M2M_TOKEN_JSON="$(curl -fsS -u "$M2M_CLIENT_ID:$M2M_SECRET" -X POST "$BASE_URL/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "scope=profile")"
M2M_ACCESS_TOKEN="$(printf '%s' "$M2M_TOKEN_JSON" | json_field access_token)"

curl -fsS -u "$M2M_CLIENT_ID:$M2M_SECRET" -X POST "$BASE_URL/oauth2/introspect" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "token=$M2M_ACCESS_TOKEN" |
  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["active"] is True; assert d["token_type"]=="access_token"'

curl -fsS -u "$M2M_CLIENT_ID:$M2M_SECRET" -X POST "$BASE_URL/oauth2/revoke" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "token=$M2M_ACCESS_TOKEN" >/dev/null

curl -fsS -u "$M2M_CLIENT_ID:$M2M_SECRET" -X POST "$BASE_URL/oauth2/introspect" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "token=$M2M_ACCESS_TOKEN" |
  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["active"] is False'

: >"$HEADERS_FILE"
curl -sS -o /dev/null -D "$HEADERS_FILE" -b "$COOKIE_JAR" -G "$BASE_URL/oauth2/logout" \
  --data-urlencode "id_token_hint=$ID_TOKEN" \
  --data-urlencode "post_logout_redirect_uri=https://client.example.test/logout" \
  --data-urlencode "state=logout-state"
LOGOUT_LOCATION="$(awk 'BEGIN{IGNORECASE=1} /^location:/{sub(/^[^:]+:[[:space:]]*/,""); sub(/\r$/,""); print; exit}' "$HEADERS_FILE")"
python3 -c 'import sys,urllib.parse; u=urllib.parse.urlparse(sys.argv[1]); q=urllib.parse.parse_qs(u.query); assert u.scheme=="https"; assert u.netloc=="client.example.test"; assert u.path=="/logout"; assert q["state"][0]=="logout-state"' "$LOGOUT_LOCATION"

echo "OpenSSO foundation and OIDC E2E flows passed."

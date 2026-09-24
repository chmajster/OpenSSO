#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${OPENSSO_E2E_URL:-http://127.0.0.1:8080}"
BOOTSTRAP_TOKEN="${OPENSSO_BOOTSTRAP_TOKEN:?OPENSSO_BOOTSTRAP_TOKEN is required}"
COOKIE_JAR="$(mktemp)"
USER_COOKIE_JAR="$(mktemp)"
HEADERS_FILE="$(mktemp)"
trap 'rm -f "$COOKIE_JAR" "$USER_COOKIE_JAR" "$HEADERS_FILE"' EXIT

json_field() {
  local field="$1"
  python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$field"
}

totp_code() {
  python3 - "$1" <<'PY'
import base64
import hashlib
import hmac
import struct
import sys
import time
secret=sys.argv[1].strip().upper()
secret += "="*((8-len(secret)%8)%8)
key=base64.b32decode(secret, casefold=True)
counter=int(time.time())//30
digest=hmac.new(key,struct.pack(">Q",counter),hashlib.sha1).digest()
offset=digest[-1]&15
value=(struct.unpack(">I",digest[offset:offset+4])[0]&0x7fffffff)%1000000
print(f"{value:06d}")
PY
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
  --data '{"username":"e2e-admin","email":"e2e-admin@example.test","display_name":"E2E Admin","password":"E2e-Initial-Password-123!"}' >/dev/null

curl -fsS -c "$COOKIE_JAR" -X POST "$BASE_URL/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  --data '{"username":"e2e-admin","password":"E2e-Initial-Password-123!"}' >/dev/null

CSRF="$(awk '$6=="opensso_csrf"{print $7}' "$COOKIE_JAR" | tail -n1)"
test -n "$CSRF"

api_mutate() {
  local method="$1"; shift
  local path="$1"; shift
  curl -fsS -b "$COOKIE_JAR" -c "$COOKIE_JAR" -X "$method" "$BASE_URL$path" \
    -H "Content-Type: application/json" \
    -H "X-CSRF-Token: $CSRF" "$@"
}

ADMIN_TOTP_SETUP="$(api_mutate POST /api/v1/me/mfa/totp/begin --data '{}')"
ADMIN_TOTP_SECRET="$(printf '%s' "$ADMIN_TOTP_SETUP" | json_field secret)"
python3 -c 'import json,sys; d=json.loads(sys.argv[1]); assert d["qr_code_data_url"].startswith("data:image/png;base64,"); assert d["otpauth_url"].startswith("otpauth://")' "$ADMIN_TOTP_SETUP"
ADMIN_TOTP_CODE="$(totp_code "$ADMIN_TOTP_SECRET")"
ADMIN_TOTP_CONFIRM="$(api_mutate POST /api/v1/me/mfa/totp/confirm --data "{\"code\":\"$ADMIN_TOTP_CODE\"}")"
python3 -c 'import json,sys; d=json.loads(sys.argv[1]); assert d["verified"] is True; assert len(d["recovery_codes"])==10' "$ADMIN_TOTP_CONFIRM"
curl -fsS -b "$COOKIE_JAR" "$BASE_URL/api/v1/me/mfa/status" |
  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["totp_enabled"] is True; assert d["session_verified"] is True; assert d["recovery_codes_remaining"]==10'

USER_JSON="$(api_mutate POST /api/v1/users --data '{"username":"e2e-user","email":"e2e-user@example.test","display_name":"E2E User","password":"Temporary-User-Password-123!"}')"
USER_ID="$(printf '%s' "$USER_JSON" | json_field id)"

GROUP_JSON="$(api_mutate POST /api/v1/groups --data '{"name":"E2E Group","description":"Integration test group"}')"
GROUP_ID="$(printf '%s' "$GROUP_JSON" | json_field id)"
api_mutate POST "/api/v1/groups/$GROUP_ID/members" --data "{\"user_id\":\"$USER_ID\"}" >/dev/null
curl -fsS -b "$COOKIE_JAR" "$BASE_URL/api/v1/groups/$GROUP_ID/members" |
  python3 -c 'import json,sys; d=json.load(sys.stdin); assert any(x["username"]=="e2e-user" for x in d["items"])'
api_mutate PATCH "/api/v1/groups/$GROUP_ID" --data '{"name":"E2E Group Updated","description":"Updated integration group"}' >/dev/null
api_mutate PUT "/api/v1/groups/$GROUP_ID/mfa-policy" --data '{"required":true}' >/dev/null
curl -fsS -b "$COOKIE_JAR" "$BASE_URL/api/v1/groups/$GROUP_ID/mfa-policy" |
  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["required"] is True'

TEMP_GROUP_JSON="$(api_mutate POST /api/v1/groups --data '{"name":"E2E Temporary Group","description":"Delete test"}')"
TEMP_GROUP_ID="$(printf '%s' "$TEMP_GROUP_JSON" | json_field id)"
api_mutate DELETE "/api/v1/groups/$TEMP_GROUP_ID" >/dev/null

ROLES_JSON="$(curl -fsS -b "$COOKIE_JAR" "$BASE_URL/api/v1/roles")"
USER_ROLE_ID="$(python3 -c 'import json,sys; d=json.load(sys.stdin); print(next(x["id"] for x in d["items"] if x["name"]=="User"))' <<<"$ROLES_JSON")"
python3 -c 'import json,sys; d=json.loads(sys.argv[1]); names={x["name"] for x in d["items"]}; required={"Super Admin","Admin","User Administrator","Application Administrator","Security Administrator","Read Only Administrator","User"}; assert required.issubset(names)' "$ROLES_JSON"
api_mutate POST "/api/v1/users/$USER_ID/roles" --data "{\"role_id\":\"$USER_ROLE_ID\"}" >/dev/null

APP_JSON="$(api_mutate POST /api/v1/applications --data '{"name":"E2E OIDC Client","public_client":true,"redirect_uris":["https://client.example.test/callback"],"post_logout_redirect_uris":["https://client.example.test/logout"],"allowed_scopes":["openid","profile","email","groups"],"initiate_login_uri":"https://client.example.test/login"}')"
APP_ID="$(printf '%s' "$APP_JSON" | json_field id)"
CLIENT_ID="$(printf '%s' "$APP_JSON" | json_field client_id)"
api_mutate POST "/api/v1/applications/$APP_ID/assign/groups" --data "{\"group_id\":\"$GROUP_ID\"}" >/dev/null
api_mutate PUT "/api/v1/applications/$APP_ID" --data '{"name":"E2E OIDC Client Updated","enabled":true,"initiate_login_uri":"https://client.example.test/login","redirect_uris":["https://client.example.test/callback"],"post_logout_redirect_uris":["https://client.example.test/logout"],"allowed_scopes":["openid","profile","email","groups"]}' >/dev/null
curl -fsS -b "$COOKIE_JAR" "$BASE_URL/api/v1/applications/$APP_ID/assignments" |
  python3 -c 'import json,sys; d=json.load(sys.stdin); assert any(x["name"]=="E2E Group Updated" for x in d["groups"])'

M2M_JSON="$(api_mutate POST /api/v1/applications --data '{"name":"E2E M2M Client","public_client":false,"redirect_uris":["https://machine.example.test/callback"],"allowed_scopes":["openid","profile"]}')"
M2M_ID="$(printf '%s' "$M2M_JSON" | json_field id)"
M2M_CLIENT_ID="$(printf '%s' "$M2M_JSON" | json_field client_id)"
M2M_SECRET="$(printf '%s' "$M2M_JSON" | json_field client_secret)"
test -n "$M2M_SECRET"
api_mutate POST "/api/v1/applications/$M2M_ID/assign/users" --data "{\"user_id\":\"$USER_ID\"}" >/dev/null
OLD_M2M_SECRET="$M2M_SECRET"
ROTATED_SECRET_JSON="$(api_mutate POST "/api/v1/applications/$M2M_ID/rotate-secret")"
M2M_SECRET="$(printf '%s' "$ROTATED_SECRET_JSON" | json_field client_secret)"
test "$M2M_SECRET" != "$OLD_M2M_SECRET"

curl -fsS -b "$COOKIE_JAR" "$BASE_URL/api/v1/applications/$APP_ID/integration" |
  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["client_id"]; assert d["issuer"].startswith("http"); assert d["client_secret_retrievable"] is False; assert d["initiate_login_uri"]=="https://client.example.test/login"'

curl -fsS -b "$COOKIE_JAR" "$BASE_URL/api/v1/dashboard" |
  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["users"] >= 2; assert d["applications"] >= 2'
curl -fsS -b "$COOKIE_JAR" "$BASE_URL/api/v1/sessions" |
  python3 -c 'import json,sys; d=json.load(sys.stdin); assert len(d["items"]) >= 1'
curl -fsS -b "$COOKIE_JAR" "$BASE_URL/api/v1/audit" |
  python3 -c 'import json,sys; d=json.load(sys.stdin); assert any(x["event"]=="USER_CREATED" for x in d["items"])'

api_mutate POST "/api/v1/users/$USER_ID/unlock" >/dev/null
api_mutate POST "/api/v1/users/$USER_ID/sessions/revoke-all" >/dev/null

POLICY="$(curl -fsS -b "$COOKIE_JAR" "$BASE_URL/api/v1/security/policy")"
python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["password_min_length"] >= 12; assert d["password_require_upper"] is True; assert d["password_require_lower"] is True; assert d["password_require_digit"] is True; assert d["password_require_symbol"] is True; assert d["lockout_threshold"] >= 3' <<<"$POLICY"


USER_LOGIN="$(curl -fsS -c "$USER_COOKIE_JAR" -X POST "$BASE_URL/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  --data '{"username":"e2e-user","password":"Temporary-User-Password-123!"}')"
python3 -c 'import json,sys; d=json.loads(sys.argv[1]); assert d["mfa_required"] is True; assert d["mfa_enrollment_required"] is True' "$USER_LOGIN"
USER_CSRF="$(awk '$6=="opensso_csrf"{print $7}' "$USER_COOKIE_JAR" | tail -n1)"
test -n "$USER_CSRF"

user_mutate() {
  local method="$1"; shift
  local path="$1"; shift
  curl -fsS -b "$USER_COOKIE_JAR" -c "$USER_COOKIE_JAR" -X "$method" "$BASE_URL$path" \
    -H "Content-Type: application/json" \
    -H "X-CSRF-Token: $USER_CSRF" "$@"
}

curl -fsS -b "$USER_COOKIE_JAR" "$BASE_URL/api/v1/me" |
  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["username"]=="e2e-user"; assert d["must_change_password"] is True; assert d["mfa_required"] is True; assert d["mfa_verified"] is False'
user_mutate POST /api/v1/me/password --data '{"current_password":"Temporary-User-Password-123!","new_password":"E2e-User-New-Password-456!"}' >/dev/null

ACCESS_BEFORE_MFA="$(curl -sS -o /dev/null -w '%{http_code}' -b "$USER_COOKIE_JAR" "$BASE_URL/api/v1/me/access")"
test "$ACCESS_BEFORE_MFA" = "403"

USER_TOTP_SETUP="$(user_mutate POST /api/v1/me/mfa/totp/begin --data '{}')"
USER_TOTP_SECRET="$(printf '%s' "$USER_TOTP_SETUP" | json_field secret)"
USER_TOTP_CODE="$(totp_code "$USER_TOTP_SECRET")"
USER_TOTP_CONFIRM="$(user_mutate POST /api/v1/me/mfa/totp/confirm --data "{\"code\":\"$USER_TOTP_CODE\"}")"
USER_RECOVERY_CODE="$(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); assert d["verified"] is True; assert len(d["recovery_codes"])==10; print(d["recovery_codes"][0])' "$USER_TOTP_CONFIRM")"

curl -fsS -b "$USER_COOKIE_JAR" "$BASE_URL/api/v1/me" |
  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["mfa_verified"] is True; assert d["must_change_password"] is False'
curl -fsS -b "$USER_COOKIE_JAR" "$BASE_URL/api/v1/me/access" |
  python3 -c 'import json,sys; d=json.load(sys.stdin); assert "User" in d["roles"]; assert d["permissions"]==[]'
curl -fsS -b "$USER_COOKIE_JAR" "$BASE_URL/api/v1/me/applications" |
  python3 -c 'import json,sys; d=json.load(sys.stdin); names={x["name"] for x in d["items"]}; assert "E2E OIDC Client Updated" in names; assert "E2E M2M Client" in names; assert any(x.get("launch_url")=="https://client.example.test/login" for x in d["items"])'
user_mutate PATCH /api/v1/me/profile --data '{"email":"e2e-user-updated@example.test","display_name":"Updated E2E User"}' >/dev/null
curl -fsS -b "$USER_COOKIE_JAR" "$BASE_URL/api/v1/me/profile" |
  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["email"]=="e2e-user-updated@example.test"; assert d["display_name"]=="Updated E2E User"'
USER_SESSIONS_JSON="$(curl -fsS -b "$USER_COOKIE_JAR" "$BASE_URL/api/v1/me/sessions")"
USER_SESSION_ID="$(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); assert len(d["items"])>=1; print(d["items"][0]["id"])' "$USER_SESSIONS_JSON")"
user_mutate DELETE "/api/v1/me/sessions/$USER_SESSION_ID" >/dev/null

USER_LOGIN_RECOVERY="$(curl -fsS -c "$USER_COOKIE_JAR" -X POST "$BASE_URL/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  --data '{"username":"e2e-user","password":"E2e-User-New-Password-456!"}')"
python3 -c 'import json,sys; d=json.loads(sys.argv[1]); assert d["mfa_required"] is True; assert d["mfa_enrollment_required"] is False' "$USER_LOGIN_RECOVERY"
USER_CSRF="$(awk '$6=="opensso_csrf"{print $7}' "$USER_COOKIE_JAR" | tail -n1)"
RECOVERY_VERIFY="$(user_mutate POST /api/v1/auth/mfa/verify --data "{\"method\":\"recovery\",\"code\":\"$USER_RECOVERY_CODE\"}")"
python3 -c 'import json,sys; d=json.loads(sys.argv[1]); assert d["verified"] is True' "$RECOVERY_VERIFY"
RECOVERY_REUSE_STATUS="$(curl -sS -o /dev/null -w '%{http_code}' -b "$USER_COOKIE_JAR" -c "$USER_COOKIE_JAR" -X POST "$BASE_URL/api/v1/auth/mfa/verify" \
  -H "Content-Type: application/json" -H "X-CSRF-Token: $USER_CSRF" \
  --data "{\"method\":\"recovery\",\"code\":\"$USER_RECOVERY_CODE\"}")"
test "$RECOVERY_REUSE_STATUS" = "401"

DISCOVERY_JSON="$(curl -fsS "$BASE_URL/.well-known/openid-configuration")"
python3 -c 'import json,sys; d=json.loads(sys.argv[1]); assert d["issuer"]; assert d["authorization_endpoint"].endswith("/oauth2/authorize"); assert "S256" in d["code_challenge_methods_supported"]' "$DISCOVERY_JSON"

OAUTH_METADATA_JSON="$(curl -fsS "$BASE_URL/.well-known/oauth-authorization-server")"
python3 -c 'import json,sys; d=json.loads(sys.argv[1]); assert "authorization_code" in d["grant_types_supported"]' "$OAUTH_METADATA_JSON"

JWKS_JSON="$(curl -fsS "$BASE_URL/.well-known/jwks.json")"
python3 -c 'import json,sys; d=json.loads(sys.argv[1]); assert len(d["keys"]) >= 1; assert d["keys"][0]["alg"]=="RS256"; assert d["keys"][0]["kty"]=="RSA"' "$JWKS_JSON"

VERIFIER='dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
CHALLENGE='E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
REDIRECT_URI='https://client.example.test/callback'
STATE='e2e-state-123'
NONCE='e2e-nonce-123'

api_mutate PUT "/api/v1/applications/$APP_ID/mfa-policy" --data '{"required":true}' >/dev/null
curl -fsS -b "$COOKIE_JAR" "$BASE_URL/api/v1/applications/$APP_ID/mfa-policy" |
  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["required"] is True'

api_mutate POST /api/v1/auth/logout >/dev/null
ADMIN_LOGIN_STEPUP="$(curl -fsS -c "$COOKIE_JAR" -X POST "$BASE_URL/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  --data '{"username":"e2e-admin","password":"E2e-Initial-Password-123!"}')"
python3 -c 'import json,sys; d=json.loads(sys.argv[1]); assert d["mfa_required"] is False' "$ADMIN_LOGIN_STEPUP"
CSRF="$(awk '$6=="opensso_csrf"{print $7}' "$COOKIE_JAR" | tail -n1)"

: >"$HEADERS_FILE"
curl -sS -o /dev/null -D "$HEADERS_FILE" -b "$COOKIE_JAR" -G "$BASE_URL/oauth2/authorize" \
  --data-urlencode "response_type=code" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "redirect_uri=$REDIRECT_URI" \
  --data-urlencode "scope=openid profile email groups" \
  --data-urlencode "state=$STATE" \
  --data-urlencode "nonce=$NONCE" \
  --data-urlencode "code_challenge=$CHALLENGE" \
  --data-urlencode "code_challenge_method=S256" \
  --data-urlencode "prompt=none"
PROMPT_NONE_LOCATION="$(awk 'BEGIN{IGNORECASE=1} /^location:/{sub(/^[^:]+:[[:space:]]*/,""); sub(/\r$/,""); print; exit}' "$HEADERS_FILE")"
python3 -c 'import sys,urllib.parse; q=urllib.parse.parse_qs(urllib.parse.urlparse(sys.argv[1]).query); assert q["error"][0]=="interaction_required"; assert q["state"][0]=="e2e-state-123"' "$PROMPT_NONE_LOCATION"

: >"$HEADERS_FILE"
curl -sS -o /dev/null -D "$HEADERS_FILE" -b "$COOKIE_JAR" -G "$BASE_URL/oauth2/authorize" \
  --data-urlencode "response_type=code" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "redirect_uri=$REDIRECT_URI" \
  --data-urlencode "scope=openid profile email groups" \
  --data-urlencode "state=$STATE" \
  --data-urlencode "nonce=$NONCE" \
  --data-urlencode "code_challenge=$CHALLENGE" \
  --data-urlencode "code_challenge_method=S256"
MFA_REDIRECT="$(awk 'BEGIN{IGNORECASE=1} /^location:/{sub(/^[^:]+:[[:space:]]*/,""); sub(/\r$/,""); print; exit}' "$HEADERS_FILE")"
python3 -c 'import sys,urllib.parse; u=urllib.parse.urlparse(sys.argv[1]); q=urllib.parse.parse_qs(u.query); assert u.path=="/"; assert q["mfa"][0]=="required"; assert q["return_to"][0].startswith("/oauth2/authorize")' "$MFA_REDIRECT"

ADMIN_TOTP_CODE="$(totp_code "$ADMIN_TOTP_SECRET")"
api_mutate POST /api/v1/auth/mfa/verify --data "{\"method\":\"totp\",\"code\":\"$ADMIN_TOTP_CODE\"}" >/dev/null
curl -fsS -b "$COOKIE_JAR" "$BASE_URL/api/v1/me" |
  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["mfa_verified"] is True'

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

OLD_SECRET_RESPONSE="$(curl -sS -u "$M2M_CLIENT_ID:$OLD_M2M_SECRET" -X POST "$BASE_URL/oauth2/token" -H "Content-Type: application/x-www-form-urlencoded" --data-urlencode "grant_type=client_credentials" --data-urlencode "scope=profile")"
python3 -c 'import json,sys; d=json.loads(sys.argv[1]); assert d["error"]=="invalid_client"' "$OLD_SECRET_RESPONSE"

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


GLOBAL_MFA_ON="$(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); d["mfa_required"]=True; print(json.dumps(d,separators=(",",":")))' "$POLICY")"
api_mutate PUT /api/v1/security/policy --data "$GLOBAL_MFA_ON" >/dev/null
curl -fsS -b "$COOKIE_JAR" "$BASE_URL/api/v1/me" |
  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["mfa_required"] is True; assert d["mfa_verified"] is True'
GLOBAL_MFA_OFF="$(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); d["mfa_required"]=False; print(json.dumps(d,separators=(",",":")))' "$POLICY")"
api_mutate PUT /api/v1/security/policy --data "$GLOBAL_MFA_OFF" >/dev/null

api_mutate POST "/api/v1/users/$USER_ID/mfa/reset" >/dev/null
curl -fsS -b "$COOKIE_JAR" "$BASE_URL/api/v1/users/$USER_ID/mfa" |
  python3 -c 'import json,sys; d=json.load(sys.stdin); s=d["status"]; assert s["totp_enabled"] is False; assert s["webauthn_credentials"]==0; assert s["recovery_codes_remaining"]==0'

MFA_AUDIT="$(curl -fsS -b "$COOKIE_JAR" "$BASE_URL/api/v1/audit")"
python3 -c 'import json,sys; d=json.loads(sys.argv[1]); events={x["event"] for x in d["items"]}; required={"MFA_ADDED","MFA_CHALLENGE_SUCCESS","MFA_RECOVERY_USED","MFA_RESET","MFA_POLICY_CHANGED"}; assert required.issubset(events), required-events if False else required.difference(events)' "$MFA_AUDIT"

api_mutate POST /api/v1/sessions/revoke-all >/dev/null

: >"$HEADERS_FILE"
curl -sS -o /dev/null -D "$HEADERS_FILE" -b "$COOKIE_JAR" -G "$BASE_URL/oauth2/logout" \
  --data-urlencode "id_token_hint=$ID_TOKEN" \
  --data-urlencode "post_logout_redirect_uri=https://client.example.test/logout" \
  --data-urlencode "state=logout-state"
LOGOUT_LOCATION="$(awk 'BEGIN{IGNORECASE=1} /^location:/{sub(/^[^:]+:[[:space:]]*/,""); sub(/\r$/,""); print; exit}' "$HEADERS_FILE")"
python3 -c 'import sys,urllib.parse; u=urllib.parse.urlparse(sys.argv[1]); q=urllib.parse.parse_qs(u.query); assert u.scheme=="https"; assert u.netloc=="client.example.test"; assert u.path=="/logout"; assert q["state"][0]=="logout-state"' "$LOGOUT_LOCATION"

echo "OpenSSO foundation and OIDC E2E flows passed."

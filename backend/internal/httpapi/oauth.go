package httpapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/chmajster/OpenSSO/backend/internal/security"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
)

type oauthClient struct {
	ApplicationID string
	Name          string
	ClientID      string
	SecretHash    *string
	Public        bool
	RequirePKCE   bool
	AllowedScopes []string
	AccessTTL     int
	IDTTL         int
	RefreshTTL    int
}

type accessClaims struct {
	Scope    string `json:"scope"`
	TokenUse string `json:"token_use"`
	jwt.RegisteredClaims
}

type idClaims struct {
	Nonce             string   `json:"nonce,omitempty"`
	Name              string   `json:"name,omitempty"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Email             string   `json:"email,omitempty"`
	EmailVerified     *bool    `json:"email_verified,omitempty"`
	Groups            []string `json:"groups,omitempty"`
	jwt.RegisteredClaims
}

var consentPage = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Authorize {{.Application}}</title></head>
<body><main><h1>Authorize {{.Application}}</h1><p>This application is requesting access to:</p><ul>{{range .Scopes}}<li>{{.}}</li>{{end}}</ul>
<form method="post" action="/oauth2/authorize/consent">
<input type="hidden" name="request_token" value="{{.RequestToken}}">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<button type="submit" name="action" value="approve">Allow</button>
<button type="submit" name="action" value="deny">Deny</button>
</form></main></body></html>`))

func (s *Server) oidcDiscovery(w http.ResponseWriter, r *http.Request) {
	issuer := s.cfg.PublicURL
	writeJSON(w, 200, map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/oauth2/authorize",
		"token_endpoint":                        issuer + "/oauth2/token",
		"userinfo_endpoint":                     issuer + "/userinfo",
		"jwks_uri":                              issuer + "/.well-known/jwks.json",
		"revocation_endpoint":                   issuer + "/oauth2/revoke",
		"introspection_endpoint":                issuer + "/oauth2/introspect",
		"end_session_endpoint":                  issuer + "/oauth2/logout",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "groups"},
		"claims_supported":                      []string{"sub", "name", "preferred_username", "email", "email_verified", "groups"},
	})
}

func (s *Server) oauthAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	issuer := s.cfg.PublicURL
	writeJSON(w, 200, map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/oauth2/authorize",
		"token_endpoint":                        issuer + "/oauth2/token",
		"jwks_uri":                              issuer + "/.well-known/jwks.json",
		"revocation_endpoint":                   issuer + "/oauth2/revoke",
		"introspection_endpoint":                issuer + "/oauth2/introspect",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "groups"},
	})
}

func (s *Server) jwks(w http.ResponseWriter, r *http.Request) {
	keys, err := s.keys.JWKS(r.Context())
	if err != nil {
		problem(w, 500, "signing key lookup failed")
		return
	}
	writeJSON(w, 200, map[string]any{"keys": keys})
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	client, redirectURI, scope, scopes, state, nonce, challenge, ok := s.validateAuthorizationRequest(w, r)
	if !ok {
		return
	}
	p, authenticated := s.sessionPrincipal(r)
	if !authenticated {
		if r.URL.Query().Get("prompt") == "none" {
			redirectOAuthError(w, r, redirectURI, state, "login_required", "authentication required")
			return
		}
		returnTo := r.URL.RequestURI()
		http.Redirect(w, r, "/?return_to="+url.QueryEscape(returnTo), http.StatusFound)
		return
	}
	if p.MustChangePassword {
		http.Redirect(w, r, "/?return_to="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
		return
	}
	mfaRequired, err := s.mfa.Required(r.Context(), p.UserID, &client.ApplicationID)
	if err != nil {
		problem(w, 500, "MFA policy lookup failed")
		return
	}
	if mfaRequired && !p.MFAVerified {
		if r.URL.Query().Get("prompt") == "none" {
			redirectOAuthError(w, r, redirectURI, state, "interaction_required", "MFA verification required")
			return
		}
		http.Redirect(w, r, "/?mfa=required&return_to="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
		return
	}

	var granted []string
	err := s.db.QueryRow(r.Context(), `SELECT granted_scopes FROM oauth_consents WHERE user_id=$1 AND application_id=$2`, p.UserID, client.ApplicationID).Scan(&granted)
	if err == nil && containsAll(granted, scopes) {
		code, err := s.storeAuthorizationCode(r.Context(), client.ApplicationID, p.UserID, redirectURI, scope, nonce, challenge)
		if err != nil {
			problem(w, 500, "authorization code creation failed")
			return
		}
		redirectAuthorizationCode(w, r, redirectURI, state, code)
		return
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		problem(w, 500, "consent lookup failed")
		return
	}
	if r.URL.Query().Get("prompt") == "none" {
		redirectOAuthError(w, r, redirectURI, state, "consent_required", "user consent required")
		return
	}

	requestToken, err := security.RandomToken(32)
	if err != nil {
		problem(w, 500, "entropy failure")
		return
	}
	_, err = s.db.Exec(r.Context(), `
		INSERT INTO oauth_authorization_requests(request_token_hash,application_id,user_id,redirect_uri,state,nonce,scope,code_challenge,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,now()+interval '5 minutes')
	`, security.SHA256String(requestToken), client.ApplicationID, p.UserID, redirectURI, state, nonce, scope, challenge)
	if err != nil {
		problem(w, 500, "authorization request creation failed")
		return
	}
	csrf, err := r.Cookie("opensso_csrf")
	if err != nil || csrf.Value == "" {
		problem(w, 403, "CSRF token unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = consentPage.Execute(w, map[string]any{
		"Application":  client.Name,
		"Scopes":       scopes,
		"RequestToken": requestToken,
		"CSRF":         csrf.Value,
	})
}

func (s *Server) authorizeConsent(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		problem(w, 400, "invalid consent form")
		return
	}
	csrfCookie, err := r.Cookie("opensso_csrf")
	if err != nil || subtle.ConstantTimeCompare([]byte(csrfCookie.Value), []byte(r.Form.Get("csrf"))) != 1 {
		problem(w, 403, "CSRF validation failed")
		return
	}
	p, authenticated := s.sessionPrincipal(r)
	if !authenticated || p.MustChangePassword {
		problem(w, 401, "authentication required")
		return
	}
	token := r.Form.Get("request_token")
	if token == "" {
		problem(w, 400, "missing authorization request")
		return
	}
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	defer tx.Rollback(r.Context())

	var id, applicationID, userID, redirectURI, state, nonce, scope, challenge string
	var expires time.Time
	var consumed *time.Time
	err = tx.QueryRow(r.Context(), `
		SELECT id,application_id,user_id,redirect_uri,state,nonce,scope,code_challenge,expires_at,consumed_at
		FROM oauth_authorization_requests WHERE request_token_hash=$1 FOR UPDATE
	`, security.SHA256String(token)).Scan(&id, &applicationID, &userID, &redirectURI, &state, &nonce, &scope, &challenge, &expires, &consumed)
	if err != nil || userID != p.UserID || consumed != nil || time.Now().After(expires) {
		problem(w, 400, "authorization request is invalid or expired")
		return
	}
	if _, err = tx.Exec(r.Context(), `UPDATE oauth_authorization_requests SET consumed_at=now() WHERE id=$1`, id); err != nil {
		problem(w, 500, "database error")
		return
	}
	if r.Form.Get("action") != "approve" {
		if err = tx.Commit(r.Context()); err != nil {
			problem(w, 500, "database error")
			return
		}
		redirectOAuthError(w, r, redirectURI, state, "access_denied", "user denied access")
		return
	}
	requested, _ := splitScope(scope)
	var existing []string
	err = tx.QueryRow(r.Context(), `SELECT granted_scopes FROM oauth_consents WHERE user_id=$1 AND application_id=$2`, userID, applicationID).Scan(&existing)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		problem(w, 500, "database error")
		return
	}
	merged := mergeScopes(existing, requested)
	if _, err = tx.Exec(r.Context(), `
		INSERT INTO oauth_consents(user_id,application_id,granted_scopes)
		VALUES($1,$2,$3)
		ON CONFLICT(user_id,application_id) DO UPDATE SET granted_scopes=EXCLUDED.granted_scopes,updated_at=now()
	`, userID, applicationID, merged); err != nil {
		problem(w, 500, "database error")
		return
	}
	code, err := security.RandomToken(32)
	if err != nil {
		problem(w, 500, "entropy failure")
		return
	}
	if _, err = tx.Exec(r.Context(), `
		INSERT INTO authorization_codes(code_hash,application_id,user_id,redirect_uri,scope,nonce,code_challenge,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,now()+interval '2 minutes')
	`, security.SHA256String(code), applicationID, userID, redirectURI, scope, nonce, challenge); err != nil {
		problem(w, 500, "database error")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		problem(w, 500, "database error")
		return
	}
	redirectAuthorizationCode(w, r, redirectURI, state, code)
}

func (s *Server) tokenEndpoint(w http.ResponseWriter, r *http.Request) {
	if !s.allowOAuthRequest(r.Context(), "token", clientIP(r), 120, time.Minute) {
		oauthJSONError(w, 429, "slow_down", "too many token requests")
		return
	}
	if err := r.ParseForm(); err != nil {
		oauthJSONError(w, 400, "invalid_request", "invalid form body")
		return
	}
	client, err := s.authenticateOAuthClient(r)
	if err != nil {
		oauthJSONError(w, 401, "invalid_client", "client authentication failed")
		return
	}
	switch r.Form.Get("grant_type") {
	case "authorization_code":
		s.authorizationCodeGrant(w, r, client)
	case "refresh_token":
		s.refreshTokenGrant(w, r, client)
	case "client_credentials":
		s.clientCredentialsGrant(w, r, client)
	default:
		oauthJSONError(w, 400, "unsupported_grant_type", "unsupported grant_type")
	}
}

func (s *Server) authorizationCodeGrant(w http.ResponseWriter, r *http.Request, client oauthClient) {
	code := r.Form.Get("code")
	redirectURI := r.Form.Get("redirect_uri")
	verifier := r.Form.Get("code_verifier")
	if code == "" || redirectURI == "" || !validPKCEVerifier(verifier) {
		oauthJSONError(w, 400, "invalid_request", "code, redirect_uri and valid code_verifier are required")
		return
	}
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		oauthJSONError(w, 500, "server_error", "database error")
		return
	}
	defer tx.Rollback(r.Context())

	var id, userID, storedRedirect, scope, nonce, challenge string
	var expires time.Time
	var consumed *time.Time
	err = tx.QueryRow(r.Context(), `
		SELECT id,user_id,redirect_uri,scope,nonce,code_challenge,expires_at,consumed_at
		FROM authorization_codes WHERE code_hash=$1 AND application_id=$2 FOR UPDATE
	`, security.SHA256String(code), client.ApplicationID).Scan(&id, &userID, &storedRedirect, &scope, &nonce, &challenge, &expires, &consumed)
	if err != nil || consumed != nil || time.Now().After(expires) || storedRedirect != redirectURI || !verifyPKCE(verifier, challenge) {
		oauthJSONError(w, 400, "invalid_grant", "authorization code is invalid, expired or already used")
		return
	}
	if _, err = tx.Exec(r.Context(), `UPDATE authorization_codes SET consumed_at=now() WHERE id=$1`, id); err != nil {
		oauthJSONError(w, 500, "server_error", "database error")
		return
	}
	response, err := s.issueUserTokens(r.Context(), tx, client, userID, scope, nonce, "", nil)
	if err != nil {
		oauthJSONError(w, 500, "server_error", "token issuance failed")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		oauthJSONError(w, 500, "server_error", "database error")
		return
	}
	writeOAuthJSON(w, 200, response)
}

func (s *Server) refreshTokenGrant(w http.ResponseWriter, r *http.Request, client oauthClient) {
	raw := r.Form.Get("refresh_token")
	if raw == "" {
		oauthJSONError(w, 400, "invalid_request", "refresh_token is required")
		return
	}
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		oauthJSONError(w, 500, "server_error", "database error")
		return
	}
	defer tx.Rollback(r.Context())
	var id, familyID, userID, scope string
	var expires time.Time
	var consumed, revoked *time.Time
	err = tx.QueryRow(r.Context(), `
		SELECT id,family_id,user_id,scope,expires_at,consumed_at,revoked_at
		FROM refresh_tokens WHERE token_hash=$1 AND application_id=$2 FOR UPDATE
	`, security.SHA256String(raw), client.ApplicationID).Scan(&id, &familyID, &userID, &scope, &expires, &consumed, &revoked)
	if err != nil {
		oauthJSONError(w, 400, "invalid_grant", "refresh token is invalid")
		return
	}
	if consumed != nil || revoked != nil {
		_, _ = tx.Exec(r.Context(), `UPDATE refresh_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE family_id=$1`, familyID)
		_ = tx.Commit(r.Context())
		_ = s.audit(r.Context(), &userID, "REFRESH_TOKEN_REUSE", "application", client.ApplicationID, "failure", r)
		oauthJSONError(w, 400, "invalid_grant", "refresh token reuse detected")
		return
	}
	if time.Now().After(expires) {
		oauthJSONError(w, 400, "invalid_grant", "refresh token expired")
		return
	}
	if _, err = tx.Exec(r.Context(), `UPDATE refresh_tokens SET consumed_at=now() WHERE id=$1`, id); err != nil {
		oauthJSONError(w, 500, "server_error", "database error")
		return
	}
	parent := id
	response, err := s.issueUserTokens(r.Context(), tx, client, userID, scope, "", familyID, &parent)
	if err != nil {
		oauthJSONError(w, 500, "server_error", "token issuance failed")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		oauthJSONError(w, 500, "server_error", "database error")
		return
	}
	writeOAuthJSON(w, 200, response)
}

func (s *Server) clientCredentialsGrant(w http.ResponseWriter, r *http.Request, client oauthClient) {
	if client.Public {
		oauthJSONError(w, 400, "unauthorized_client", "public clients cannot use client_credentials")
		return
	}
	scope, scopes, err := normalizeRequestedScope(r.Form.Get("scope"))
	if err != nil || !containsAll(client.AllowedScopes, scopes) || contains(scopes, "openid") {
		oauthJSONError(w, 400, "invalid_scope", "requested scope is not allowed for client_credentials")
		return
	}
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		oauthJSONError(w, 500, "server_error", "database error")
		return
	}
	defer tx.Rollback(r.Context())
	response, err := s.issueAccessToken(r.Context(), tx, client, client.ClientID, nil, scope)
	if err != nil {
		oauthJSONError(w, 500, "server_error", "token issuance failed")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		oauthJSONError(w, 500, "server_error", "database error")
		return
	}
	writeOAuthJSON(w, 200, response)
}

func (s *Server) userinfo(w http.ResponseWriter, r *http.Request) {
	raw := bearerToken(r)
	if raw == "" {
		oauthJSONError(w, 401, "invalid_token", "bearer token required")
		return
	}
	claims, err := s.parseAccessToken(r.Context(), raw)
	if err != nil || claims.TokenUse != "access" {
		oauthJSONError(w, 401, "invalid_token", "access token is invalid")
		return
	}
	var userID, scope string
	err = s.db.QueryRow(r.Context(), `
		SELECT COALESCE(user_id::text,''),scope
		FROM oauth_access_tokens WHERE jti=$1 AND revoked_at IS NULL AND expires_at>now()
	`, claims.ID).Scan(&userID, &scope)
	if err != nil || userID == "" || userID != claims.Subject {
		oauthJSONError(w, 401, "invalid_token", "access token is inactive")
		return
	}
	var username, email, displayName string
	var active bool
	if err = s.db.QueryRow(r.Context(), `SELECT username,email,display_name,active FROM users WHERE id=$1`, userID).Scan(&username, &email, &displayName, &active); err != nil || !active {
		oauthJSONError(w, 401, "invalid_token", "user is inactive")
		return
	}
	scopes, _ := splitScope(scope)
	out := map[string]any{"sub": userID}
	if contains(scopes, "profile") {
		out["name"] = displayName
		out["preferred_username"] = username
	}
	if contains(scopes, "email") {
		out["email"] = email
		out["email_verified"] = false
	}
	if contains(scopes, "groups") {
		out["groups"] = s.userGroups(r.Context(), userID)
	}
	writeOAuthJSON(w, 200, out)
}

func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthJSONError(w, 400, "invalid_request", "invalid form body")
		return
	}
	client, err := s.authenticateOAuthClient(r)
	if err != nil {
		oauthJSONError(w, 401, "invalid_client", "client authentication failed")
		return
	}
	raw := r.Form.Get("token")
	if raw == "" {
		oauthJSONError(w, 400, "invalid_request", "token is required")
		return
	}
	var familyID string
	err = s.db.QueryRow(r.Context(), `SELECT family_id FROM refresh_tokens WHERE token_hash=$1 AND application_id=$2`, security.SHA256String(raw), client.ApplicationID).Scan(&familyID)
	if err == nil {
		_, _ = s.db.Exec(r.Context(), `UPDATE refresh_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE family_id=$1`, familyID)
		w.WriteHeader(http.StatusOK)
		return
	}
	if claims, parseErr := s.parseAccessToken(r.Context(), raw); parseErr == nil && audienceContains(claims.Audience, client.ClientID) {
		_, _ = s.db.Exec(r.Context(), `UPDATE oauth_access_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE jti=$1 AND application_id=$2`, claims.ID, client.ApplicationID)
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) introspectToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthJSONError(w, 400, "invalid_request", "invalid form body")
		return
	}
	client, err := s.authenticateOAuthClient(r)
	if err != nil || client.Public {
		oauthJSONError(w, 401, "invalid_client", "confidential client authentication required")
		return
	}
	raw := r.Form.Get("token")
	if raw == "" {
		oauthJSONError(w, 400, "invalid_request", "token is required")
		return
	}
	var userID, scope string
	var expires time.Time
	var consumed, revoked *time.Time
	err = s.db.QueryRow(r.Context(), `
		SELECT user_id,scope,expires_at,consumed_at,revoked_at
		FROM refresh_tokens WHERE token_hash=$1 AND application_id=$2
	`, security.SHA256String(raw), client.ApplicationID).Scan(&userID, &scope, &expires, &consumed, &revoked)
	if err == nil {
		active := consumed == nil && revoked == nil && time.Now().Before(expires)
		writeOAuthJSON(w, 200, map[string]any{"active": active, "client_id": client.ClientID, "sub": userID, "scope": scope, "exp": expires.Unix(), "token_type": "refresh_token"})
		return
	}
	claims, err := s.parseAccessToken(r.Context(), raw)
	if err != nil || !audienceContains(claims.Audience, client.ClientID) {
		writeOAuthJSON(w, 200, map[string]any{"active": false})
		return
	}
	var dbScope string
	var dbExpires time.Time
	var dbRevoked *time.Time
	err = s.db.QueryRow(r.Context(), `SELECT scope,expires_at,revoked_at FROM oauth_access_tokens WHERE jti=$1 AND application_id=$2`, claims.ID, client.ApplicationID).Scan(&dbScope, &dbExpires, &dbRevoked)
	if err != nil {
		writeOAuthJSON(w, 200, map[string]any{"active": false})
		return
	}
	writeOAuthJSON(w, 200, map[string]any{
		"active":     dbRevoked == nil && time.Now().Before(dbExpires),
		"client_id":  client.ClientID,
		"sub":        claims.Subject,
		"scope":      dbScope,
		"exp":        dbExpires.Unix(),
		"iat":        claims.IssuedAt.Unix(),
		"token_type": "access_token",
	})
}

func (s *Server) oauthLogout(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	postLogout := r.Form.Get("post_logout_redirect_uri")
	hint := r.Form.Get("id_token_hint")
	if postLogout != "" {
		if hint == "" {
			problem(w, 400, "id_token_hint is required with post_logout_redirect_uri")
			return
		}
		claims, err := s.parseIDToken(r.Context(), hint)
		if err != nil || len(claims.Audience) == 0 {
			problem(w, 400, "invalid id_token_hint")
			return
		}
		clientID := claims.Audience[0]
		var ok bool
		err = s.db.QueryRow(r.Context(), `
			SELECT EXISTS(
				SELECT 1 FROM oauth_post_logout_redirect_uris p
				JOIN oauth_clients c ON c.application_id=p.application_id
				WHERE c.client_id=$1 AND p.redirect_uri=$2
			)
		`, clientID, postLogout).Scan(&ok)
		if err != nil || !ok {
			problem(w, 400, "post_logout_redirect_uri is not registered")
			return
		}
	}
	if cookie, err := r.Cookie("opensso_session"); err == nil {
		_, _ = s.db.Exec(r.Context(), `UPDATE sessions SET revoked_at=now() WHERE token_hash=$1 AND revoked_at IS NULL`, security.SHA256String(cookie.Value))
	}
	s.clearSessionCookies(w)
	if postLogout != "" {
		target, _ := url.Parse(postLogout)
		if state := r.Form.Get("state"); state != "" {
			q := target.Query()
			q.Set("state", state)
			target.RawQuery = q.Encode()
		}
		http.Redirect(w, r, target.String(), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) listSigningKeys(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query(r.Context(), `SELECT kid,algorithm,active,created_at,retired_at FROM signing_keys ORDER BY created_at DESC`)
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var kid, algorithm string
		var active bool
		var created time.Time
		var retired *time.Time
		if err := rows.Scan(&kid, &algorithm, &active, &created, &retired); err != nil {
			problem(w, 500, "database error")
			return
		}
		items = append(items, map[string]any{"kid": kid, "algorithm": algorithm, "active": active, "created_at": created, "retired_at": retired})
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) rotateSigningKey(w http.ResponseWriter, r *http.Request) {
	key, err := s.keys.Rotate(r.Context())
	if err != nil {
		problem(w, 500, "signing key rotation failed")
		return
	}
	p := r.Context().Value(principalKey).(principal)
	_ = s.audit(r.Context(), &p.UserID, "SIGNING_KEY_ROTATED", "signing_key", key.Kid, "success", r)
	writeJSON(w, 201, map[string]string{"kid": key.Kid, "algorithm": "RS256"})
}

func (s *Server) validateAuthorizationRequest(w http.ResponseWriter, r *http.Request) (oauthClient, string, string, []string, string, string, string, bool) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	nonce := q.Get("nonce")
	challenge := q.Get("code_challenge")
	if q.Get("response_type") != "code" || clientID == "" || redirectURI == "" || state == "" {
		problem(w, 400, "invalid authorization request")
		return oauthClient{}, "", "", nil, "", "", "", false
	}
	client, err := s.loadOAuthClient(r.Context(), clientID)
	if err != nil {
		problem(w, 400, "unknown or disabled client")
		return oauthClient{}, "", "", nil, "", "", "", false
	}
	var redirectOK bool
	if err = s.db.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM oauth_redirect_uris WHERE application_id=$1 AND redirect_uri=$2)`, client.ApplicationID, redirectURI).Scan(&redirectOK); err != nil || !redirectOK {
		problem(w, 400, "redirect_uri is not registered")
		return oauthClient{}, "", "", nil, "", "", "", false
	}
	if q.Get("code_challenge_method") != "S256" || challenge == "" {
		redirectOAuthError(w, r, redirectURI, state, "invalid_request", "PKCE S256 is required")
		return oauthClient{}, "", "", nil, "", "", "", false
	}
	scope, scopes, err := normalizeRequestedScope(q.Get("scope"))
	if err != nil || !contains(scopes, "openid") || !containsAll(client.AllowedScopes, scopes) {
		redirectOAuthError(w, r, redirectURI, state, "invalid_scope", "requested scopes are not allowed")
		return oauthClient{}, "", "", nil, "", "", "", false
	}
	return client, redirectURI, scope, scopes, state, nonce, challenge, true
}

func (s *Server) loadOAuthClient(ctx context.Context, clientID string) (oauthClient, error) {
	var c oauthClient
	err := s.db.QueryRow(ctx, `
		SELECT a.id,a.name,oc.client_id,oc.client_secret_hash,oc.public_client,oc.require_pkce,
		       oc.allowed_scopes,oc.access_token_ttl_seconds,oc.id_token_ttl_seconds,oc.refresh_token_ttl_seconds
		FROM oauth_clients oc JOIN applications a ON a.id=oc.application_id
		WHERE oc.client_id=$1 AND a.enabled=true
	`, clientID).Scan(&c.ApplicationID, &c.Name, &c.ClientID, &c.SecretHash, &c.Public, &c.RequirePKCE, &c.AllowedScopes, &c.AccessTTL, &c.IDTTL, &c.RefreshTTL)
	return c, err
}

func (s *Server) authenticateOAuthClient(r *http.Request) (oauthClient, error) {
	basicID, basicSecret, hasBasic := r.BasicAuth()
	clientID := r.Form.Get("client_id")
	secret := r.Form.Get("client_secret")
	if hasBasic {
		clientID = basicID
		secret = basicSecret
	}
	if clientID == "" {
		return oauthClient{}, errors.New("missing client_id")
	}
	client, err := s.loadOAuthClient(r.Context(), clientID)
	if err != nil {
		return oauthClient{}, err
	}
	if client.Public {
		if hasBasic || secret != "" {
			return oauthClient{}, errors.New("public client must not authenticate with secret")
		}
		return client, nil
	}
	if secret == "" || client.SecretHash == nil {
		return oauthClient{}, errors.New("missing client secret")
	}
	actual := security.SHA256String(secret)
	if subtle.ConstantTimeCompare([]byte(actual), []byte(*client.SecretHash)) != 1 {
		return oauthClient{}, errors.New("invalid client secret")
	}
	return client, nil
}

func (s *Server) storeAuthorizationCode(ctx context.Context, applicationID, userID, redirectURI, scope, nonce, challenge string) (string, error) {
	code, err := security.RandomToken(32)
	if err != nil {
		return "", err
	}
	_, err = s.db.Exec(ctx, `
		INSERT INTO authorization_codes(code_hash,application_id,user_id,redirect_uri,scope,nonce,code_challenge,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,now()+interval '2 minutes')
	`, security.SHA256String(code), applicationID, userID, redirectURI, scope, nonce, challenge)
	return code, err
}

func (s *Server) issueUserTokens(ctx context.Context, tx pgx.Tx, client oauthClient, userID, scope, nonce, familyID string, parentID *string) (map[string]any, error) {
	response, err := s.issueAccessToken(ctx, tx, client, userID, &userID, scope)
	if err != nil {
		return nil, err
	}
	scopes, _ := splitScope(scope)
	if contains(scopes, "openid") {
		idToken, err := s.signIDToken(ctx, client, userID, scope, nonce)
		if err != nil {
			return nil, err
		}
		response["id_token"] = idToken
	}
	refresh, err := security.RandomToken(48)
	if err != nil {
		return nil, err
	}
	if familyID == "" {
		familyID, err = security.RandomUUID()
		if err != nil {
			return nil, err
		}
	}
	expires := time.Now().UTC().Add(time.Duration(client.RefreshTTL) * time.Second)
	if _, err = tx.Exec(ctx, `
		INSERT INTO refresh_tokens(token_hash,family_id,parent_id,application_id,user_id,scope,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7)
	`, security.SHA256String(refresh), familyID, parentID, client.ApplicationID, userID, scope, expires); err != nil {
		return nil, err
	}
	response["refresh_token"] = refresh
	return response, nil
}

func (s *Server) issueAccessToken(ctx context.Context, tx pgx.Tx, client oauthClient, subject string, userID *string, scope string) (map[string]any, error) {
	key, err := s.keys.Active(ctx)
	if err != nil {
		return nil, err
	}
	jti, err := security.RandomUUID()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	expires := now.Add(time.Duration(client.AccessTTL) * time.Second)
	claims := accessClaims{
		Scope:    scope,
		TokenUse: "access",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.cfg.PublicURL,
			Subject:   subject,
			Audience:  jwt.ClaimStrings{client.ClientID},
			ExpiresAt: jwt.NewNumericDate(expires),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        jti,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = key.Kid
	signed, err := token.SignedString(key.PrivateKey)
	if err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `
		INSERT INTO oauth_access_tokens(jti,application_id,user_id,subject,scope,expires_at)
		VALUES($1,$2,$3,$4,$5,$6)
	`, jti, client.ApplicationID, userID, subject, scope, expires); err != nil {
		return nil, err
	}
	return map[string]any{
		"access_token": signed,
		"token_type":   "Bearer",
		"expires_in":   client.AccessTTL,
		"scope":        scope,
	}, nil
}

func (s *Server) signIDToken(ctx context.Context, client oauthClient, userID, scope, nonce string) (string, error) {
	key, err := s.keys.Active(ctx)
	if err != nil {
		return "", err
	}
	var username, email, displayName string
	var active bool
	if err = s.db.QueryRow(ctx, `SELECT username,email,display_name,active FROM users WHERE id=$1`, userID).Scan(&username, &email, &displayName, &active); err != nil || !active {
		return "", errors.New("user is inactive")
	}
	now := time.Now().UTC()
	claims := idClaims{
		Nonce: nonce,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.cfg.PublicURL,
			Subject:   userID,
			Audience:  jwt.ClaimStrings{client.ClientID},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(client.IDTTL) * time.Second)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	scopes, _ := splitScope(scope)
	if contains(scopes, "profile") {
		claims.Name = displayName
		claims.PreferredUsername = username
	}
	if contains(scopes, "email") {
		verified := false
		claims.Email = email
		claims.EmailVerified = &verified
	}
	if contains(scopes, "groups") {
		claims.Groups = s.userGroups(ctx, userID)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = key.Kid
	return token.SignedString(key.PrivateKey)
}

func (s *Server) parseAccessToken(ctx context.Context, raw string) (*accessClaims, error) {
	claims := &accessClaims{}
	token, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != "RS256" {
			return nil, errors.New("unexpected signing algorithm")
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("missing kid")
		}
		return s.keys.PublicKeyByKID(ctx, kid)
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(s.cfg.PublicURL), jwt.WithExpirationRequired())
	if err != nil || !token.Valid {
		return nil, errors.New("invalid access token")
	}
	return claims, nil
}

func (s *Server) parseIDToken(ctx context.Context, raw string) (*idClaims, error) {
	claims := &idClaims{}
	token, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != "RS256" {
			return nil, errors.New("unexpected signing algorithm")
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("missing kid")
		}
		return s.keys.PublicKeyByKID(ctx, kid)
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(s.cfg.PublicURL), jwt.WithExpirationRequired())
	if err != nil || !token.Valid {
		return nil, errors.New("invalid id token")
	}
	return claims, nil
}

func (s *Server) userGroups(ctx context.Context, userID string) []string {
	rows, err := s.db.Query(ctx, `SELECT g.name FROM group_memberships gm JOIN groups g ON g.id=gm.group_id WHERE gm.user_id=$1 ORDER BY g.name`, userID)
	if err != nil {
		return []string{}
	}
	defer rows.Close()
	groups := []string{}
	for rows.Next() {
		var name string
		if rows.Scan(&name) == nil {
			groups = append(groups, name)
		}
	}
	return groups
}

func (s *Server) sessionPrincipal(r *http.Request) (principal, bool) {
	cookie, err := r.Cookie("opensso_session")
	if err != nil {
		return principal{}, false
	}
	var p principal
	err = s.db.QueryRow(r.Context(), `
		SELECT s.id,u.id,u.username,u.must_change_password,(s.mfa_verified_at IS NOT NULL)
		FROM sessions s JOIN users u ON u.id=s.user_id
		WHERE s.token_hash=$1 AND s.revoked_at IS NULL AND s.expires_at>now() AND u.active=true
	`, security.SHA256String(cookie.Value)).Scan(&p.SessionID, &p.UserID, &p.Username, &p.MustChangePassword, &p.MFAVerified)
	if err != nil {
		return principal{}, false
	}
	_, _ = s.db.Exec(r.Context(), `UPDATE sessions SET last_seen_at=now() WHERE id=$1`, p.SessionID)
	return p, true
}

func (s *Server) allowOAuthRequest(ctx context.Context, bucket, key string, limit int64, ttl time.Duration) bool {
	redisKey := "opensso:oauth:" + bucket + ":" + key
	n, err := s.redis.Incr(ctx, redisKey).Result()
	if err != nil {
		return false
	}
	if n == 1 {
		_ = s.redis.Expire(ctx, redisKey, ttl).Err()
	}
	return n <= limit
}

func (s *Server) clearSessionCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "opensso_session", Value: "", Path: "/", HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "opensso_csrf", Value: "", Path: "/", HttpOnly: false, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

func normalizeRequestedScope(raw string) (string, []string, error) {
	scopes, err := splitScope(raw)
	if err != nil {
		return "", nil, err
	}
	return strings.Join(scopes, " "), scopes, nil
}

func splitScope(raw string) ([]string, error) {
	fields := strings.Fields(raw)
	seen := map[string]bool{}
	out := make([]string, 0, len(fields))
	for _, scope := range fields {
		if scope == "" {
			return nil, errors.New("invalid scope")
		}
		for _, ch := range scope {
			if ch <= 0x20 || ch == 0x7f || ch == 34 || ch == 92 {
				return nil, errors.New("invalid scope")
			}
		}
		if !seen[scope] {
			seen[scope] = true
			out = append(out, scope)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("scope is required")
	}
	return out, nil
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsAll(allowed, requested []string) bool {
	for _, scope := range requested {
		if !contains(allowed, scope) {
			return false
		}
	}
	return true
}

func mergeScopes(a, b []string) []string {
	out := append([]string(nil), a...)
	for _, value := range b {
		if !contains(out, value) {
			out = append(out, value)
		}
	}
	return out
}

func validPKCEVerifier(value string) bool {
	if len(value) < 43 || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') && !strings.ContainsRune("-._~", c) {
			return false
		}
	}
	return true
}

func verifyPKCE(verifier, expected string) bool {
	if !validPKCEVerifier(verifier) {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	actual := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) == 1
}

func redirectAuthorizationCode(w http.ResponseWriter, r *http.Request, redirectURI, state, code string) {
	target, _ := url.Parse(redirectURI)
	q := target.Query()
	q.Set("code", code)
	q.Set("state", state)
	target.RawQuery = q.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func redirectOAuthError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, description string) {
	target, err := url.Parse(redirectURI)
	if err != nil {
		problem(w, 400, description)
		return
	}
	q := target.Query()
	q.Set("error", code)
	if description != "" {
		q.Set("error_description", description)
	}
	if state != "" {
		q.Set("state", state)
	}
	target.RawQuery = q.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if len(header) < 8 || !strings.EqualFold(header[:7], "Bearer ") {
		return ""
	}
	return strings.TrimSpace(header[7:])
}

func audienceContains(values jwt.ClaimStrings, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func oauthJSONError(w http.ResponseWriter, status int, code, description string) {
	writeOAuthJSON(w, status, map[string]string{"error": code, "error_description": description})
}

func writeOAuthJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

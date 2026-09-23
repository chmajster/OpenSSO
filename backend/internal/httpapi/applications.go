package httpapi

import (
	"net/http"

	"github.com/chmajster/OpenSSO/backend/internal/security"
)

func (s *Server) applicationIntegration(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var protocol string
	if err := s.db.QueryRow(r.Context(), `SELECT protocol FROM applications WHERE id=$1`, id).Scan(&protocol); err != nil {
		problem(w, 404, "application not found")
		return
	}
	if protocol == "saml" {
		s.samlApplicationIntegration(w, r)
		return
	}
	if protocol != "oidc" {
		problem(w, 404, "unsupported application protocol")
		return
	}
	var name, clientID string
	var public bool
	var scopes []string
	var initiateLoginURI *string
	err := s.db.QueryRow(r.Context(), `
		SELECT a.name,c.client_id,c.public_client,c.allowed_scopes,c.initiate_login_uri
		FROM applications a JOIN oauth_clients c ON c.application_id=a.id
		WHERE a.id=$1
	`, id).Scan(&name, &clientID, &public, &scopes, &initiateLoginURI)
	if err != nil {
		problem(w, 404, "application not found")
		return
	}
	redirects, err := s.stringColumn(r, `SELECT redirect_uri FROM oauth_redirect_uris WHERE application_id=$1 ORDER BY redirect_uri`, id)
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	logoutRedirects, err := s.stringColumn(r, `SELECT redirect_uri FROM oauth_post_logout_redirect_uris WHERE application_id=$1 ORDER BY redirect_uri`, id)
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	writeJSON(w, 200, map[string]any{
		"name":                      name,
		"issuer":                    s.cfg.PublicURL,
		"authorization_url":         s.cfg.PublicURL + "/oauth2/authorize",
		"token_url":                 s.cfg.PublicURL + "/oauth2/token",
		"userinfo_url":              s.cfg.PublicURL + "/userinfo",
		"jwks_url":                  s.cfg.PublicURL + "/.well-known/jwks.json",
		"logout_url":                s.cfg.PublicURL + "/oauth2/logout",
		"client_id":                 clientID,
		"public_client":             public,
		"client_secret_retrievable": false,
		"initiate_login_uri":        initiateLoginURI,
		"scopes":                    scopes,
		"redirect_uris":             redirects,
		"post_logout_redirect_uris": logoutRedirects,
	})
}

func (s *Server) rotateClientSecret(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var public bool
	if err := s.db.QueryRow(r.Context(), `SELECT public_client FROM oauth_clients WHERE application_id=$1`, id).Scan(&public); err != nil {
		problem(w, 404, "application not found")
		return
	}
	if public {
		problem(w, 400, "public clients do not have client secrets")
		return
	}
	secret, err := security.RandomToken(32)
	if err != nil {
		problem(w, 500, "entropy failure")
		return
	}
	if _, err = s.db.Exec(r.Context(), `UPDATE oauth_clients SET client_secret_hash=$1 WHERE application_id=$2`, security.SHA256String(secret), id); err != nil {
		problem(w, 500, "database error")
		return
	}
	p := r.Context().Value(principalKey).(principal)
	_ = s.audit(r.Context(), &p.UserID, "CLIENT_SECRET_ROTATED", "application", id, "success", r)
	writeJSON(w, 200, map[string]string{"client_secret": secret})
}

func (s *Server) stringColumn(r *http.Request, query string, args ...any) ([]string, error) {
	rows, err := s.db.Query(r.Context(), query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := []string{}
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

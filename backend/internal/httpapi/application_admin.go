package httpapi

import (
	"net/http"
	"net/url"
	"strings"
)

type applicationUpdateInput struct {
	Name                   string   `json:"name"`
	Enabled                bool     `json:"enabled"`
	InitiateLoginURI       string   `json:"initiate_login_uri"`
	RedirectURIs           []string `json:"redirect_uris"`
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris"`
	AllowedScopes          []string `json:"allowed_scopes"`
}

func validateApplicationURI(raw string) bool {
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	return err == nil && u.Scheme != "" && u.Host != "" && u.Fragment == "" && !strings.Contains(raw, "*")
}

func (s *Server) updateApplication(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in applicationUpdateInput
	if decodeJSON(w, r, &in) != nil {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.RedirectURIs) == 0 {
		problem(w, 400, "application name and at least one redirect URI are required")
		return
	}
	for _, raw := range append(append([]string{}, in.RedirectURIs...), in.PostLogoutRedirectURIs...) {
		if !validateApplicationURI(raw) {
			problem(w, 400, "invalid redirect URI")
			return
		}
	}
	if in.InitiateLoginURI != "" && !validateApplicationURI(in.InitiateLoginURI) {
		problem(w, 400, "invalid initiate_login_uri")
		return
	}
	if len(in.AllowedScopes) == 0 {
		problem(w, 400, "at least one allowed scope is required")
		return
	}
	_, scopes, err := normalizeRequestedScope(strings.Join(in.AllowedScopes, " "))
	if err != nil || !contains(scopes, "openid") {
		problem(w, 400, "OIDC applications must allow the openid scope")
		return
	}

	tx, err := s.db.Begin(r.Context())
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	defer tx.Rollback(r.Context())

	tag, err := tx.Exec(r.Context(), `
		UPDATE applications SET name=$1,enabled=$2 WHERE id=$3
	`, in.Name, in.Enabled, id)
	if err != nil {
		problem(w, 409, "application name already exists or update failed")
		return
	}
	if tag.RowsAffected() == 0 {
		problem(w, 404, "application not found")
		return
	}

	var initiate any
	if in.InitiateLoginURI != "" {
		initiate = in.InitiateLoginURI
	}
	if _, err = tx.Exec(r.Context(), `
		UPDATE oauth_clients SET initiate_login_uri=$1,allowed_scopes=$2
		WHERE application_id=$3
	`, initiate, scopes, id); err != nil {
		problem(w, 500, "database error")
		return
	}
	if _, err = tx.Exec(r.Context(), `DELETE FROM oauth_redirect_uris WHERE application_id=$1`, id); err != nil {
		problem(w, 500, "database error")
		return
	}
	for _, redirectURI := range in.RedirectURIs {
		if _, err = tx.Exec(r.Context(), `
			INSERT INTO oauth_redirect_uris(application_id,redirect_uri) VALUES($1,$2)
		`, id, redirectURI); err != nil {
			problem(w, 500, "database error")
			return
		}
	}
	if _, err = tx.Exec(r.Context(), `DELETE FROM oauth_post_logout_redirect_uris WHERE application_id=$1`, id); err != nil {
		problem(w, 500, "database error")
		return
	}
	for _, redirectURI := range in.PostLogoutRedirectURIs {
		if _, err = tx.Exec(r.Context(), `
			INSERT INTO oauth_post_logout_redirect_uris(application_id,redirect_uri) VALUES($1,$2)
		`, id, redirectURI); err != nil {
			problem(w, 500, "database error")
			return
		}
	}

	p := r.Context().Value(principalKey).(principal)
	if err = s.auditTx(r.Context(), tx, &p.UserID, "APPLICATION_UPDATED", "application", id, "success", r); err != nil {
		problem(w, 500, "audit error")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		problem(w, 500, "database error")
		return
	}
	writeJSON(w, 200, map[string]any{
		"id": id, "name": in.Name, "enabled": in.Enabled,
		"initiate_login_uri": in.InitiateLoginURI, "allowed_scopes": scopes,
	})
}

func (s *Server) applicationAssignments(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var exists bool
	if err := s.db.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM applications WHERE id=$1)`, id).Scan(&exists); err != nil || !exists {
		problem(w, 404, "application not found")
		return
	}
	userRows, err := s.db.Query(r.Context(), `
		SELECT u.id,u.username,u.email,u.display_name
		FROM application_user_assignments a
		JOIN users u ON u.id=a.user_id
		WHERE a.application_id=$1
		ORDER BY u.username
	`, id)
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	users := []map[string]any{}
	for userRows.Next() {
		var userID, username, email, displayName string
		if err := userRows.Scan(&userID, &username, &email, &displayName); err != nil {
			userRows.Close()
			problem(w, 500, "database error")
			return
		}
		users = append(users, map[string]any{
			"id": userID, "username": username, "email": email, "display_name": displayName,
		})
	}
	userRows.Close()

	groupRows, err := s.db.Query(r.Context(), `
		SELECT g.id,g.name,g.description
		FROM application_group_assignments a
		JOIN groups g ON g.id=a.group_id
		WHERE a.application_id=$1
		ORDER BY g.name
	`, id)
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	defer groupRows.Close()
	groups := []map[string]any{}
	for groupRows.Next() {
		var groupID, name, description string
		if err := groupRows.Scan(&groupID, &name, &description); err != nil {
			problem(w, 500, "database error")
			return
		}
		groups = append(groups, map[string]any{
			"id": groupID, "name": name, "description": description,
		})
	}
	writeJSON(w, 200, map[string]any{"users": users, "groups": groups})
}

func (s *Server) assignApplicationUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in struct {
		UserID string `json:"user_id"`
	}
	if decodeJSON(w, r, &in) != nil {
		return
	}
	if _, err := s.db.Exec(r.Context(), `
		INSERT INTO application_user_assignments(application_id,user_id)
		VALUES($1,$2) ON CONFLICT DO NOTHING
	`, id, in.UserID); err != nil {
		problem(w, 400, "invalid application or user")
		return
	}
	p := r.Context().Value(principalKey).(principal)
	_ = s.audit(r.Context(), &p.UserID, "APPLICATION_ASSIGNMENT_CHANGED", "application", id, "success", r)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) removeApplicationUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	userID := r.PathValue("userId")
	tag, err := s.db.Exec(r.Context(), `
		DELETE FROM application_user_assignments
		WHERE application_id=$1 AND user_id=$2
	`, id, userID)
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	if tag.RowsAffected() == 0 {
		problem(w, 404, "application assignment not found")
		return
	}
	p := r.Context().Value(principalKey).(principal)
	_ = s.audit(r.Context(), &p.UserID, "APPLICATION_ASSIGNMENT_CHANGED", "application", id, "success", r)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) assignApplicationGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in struct {
		GroupID string `json:"group_id"`
	}
	if decodeJSON(w, r, &in) != nil {
		return
	}
	if _, err := s.db.Exec(r.Context(), `
		INSERT INTO application_group_assignments(application_id,group_id)
		VALUES($1,$2) ON CONFLICT DO NOTHING
	`, id, in.GroupID); err != nil {
		problem(w, 400, "invalid application or group")
		return
	}
	p := r.Context().Value(principalKey).(principal)
	_ = s.audit(r.Context(), &p.UserID, "APPLICATION_ASSIGNMENT_CHANGED", "application", id, "success", r)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) removeApplicationGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	groupID := r.PathValue("groupId")
	tag, err := s.db.Exec(r.Context(), `
		DELETE FROM application_group_assignments
		WHERE application_id=$1 AND group_id=$2
	`, id, groupID)
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	if tag.RowsAffected() == 0 {
		problem(w, 404, "application assignment not found")
		return
	}
	p := r.Context().Value(principalKey).(principal)
	_ = s.audit(r.Context(), &p.UserID, "APPLICATION_ASSIGNMENT_CHANGED", "application", id, "success", r)
	w.WriteHeader(http.StatusNoContent)
}

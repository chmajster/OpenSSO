package httpapi

import (
	"net/http"
	"strings"
	"time"
)

func (s *Server) myAccess(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(principalKey).(principal)

	roleRows, err := s.db.Query(r.Context(), `
		SELECT r.name
		FROM role_assignments ra
		JOIN roles r ON r.id=ra.role_id
		WHERE ra.user_id=$1
		ORDER BY r.name
	`, p.UserID)
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	roles := []string{}
	for roleRows.Next() {
		var name string
		if err := roleRows.Scan(&name); err != nil {
			roleRows.Close()
			problem(w, 500, "database error")
			return
		}
		roles = append(roles, name)
	}
	roleRows.Close()

	permissionRows, err := s.db.Query(r.Context(), `
		SELECT DISTINCT p.name
		FROM role_assignments ra
		JOIN role_permissions rp ON rp.role_id=ra.role_id
		JOIN permissions p ON p.id=rp.permission_id
		WHERE ra.user_id=$1
		ORDER BY p.name
	`, p.UserID)
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	defer permissionRows.Close()
	permissions := []string{}
	for permissionRows.Next() {
		var name string
		if err := permissionRows.Scan(&name); err != nil {
			problem(w, 500, "database error")
			return
		}
		permissions = append(permissions, name)
	}
	writeJSON(w, 200, map[string]any{"roles": roles, "permissions": permissions})
}

func (s *Server) myProfile(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(principalKey).(principal)
	var username, email, displayName string
	var created time.Time
	if err := s.db.QueryRow(r.Context(), `
		SELECT username,email,display_name,created_at
		FROM users WHERE id=$1
	`, p.UserID).Scan(&username, &email, &displayName, &created); err != nil {
		problem(w, 404, "user not found")
		return
	}
	writeJSON(w, 200, map[string]any{
		"id": p.UserID, "username": username, "email": email,
		"display_name": displayName, "created_at": created,
	})
}

func (s *Server) updateMyProfile(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(principalKey).(principal)
	var in struct {
		Email       string `json:"email"`
		DisplayName string `json:"display_name"`
	}
	if decodeJSON(w, r, &in) != nil {
		return
	}
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	if !strings.Contains(in.Email, "@") {
		problem(w, 400, "invalid email")
		return
	}
	tag, err := s.db.Exec(r.Context(), `
		UPDATE users SET email=$1,display_name=$2,updated_at=now()
		WHERE id=$3
	`, in.Email, strings.TrimSpace(in.DisplayName), p.UserID)
	if err != nil {
		problem(w, 409, "email already exists or profile update failed")
		return
	}
	if tag.RowsAffected() == 0 {
		problem(w, 404, "user not found")
		return
	}
	_ = s.audit(r.Context(), &p.UserID, "USER_UPDATED", "user", p.UserID, "success", r)
	writeJSON(w, 200, map[string]any{
		"id": p.UserID, "email": in.Email, "display_name": strings.TrimSpace(in.DisplayName),
	})
}

func (s *Server) mySessions(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(principalKey).(principal)
	rows, err := s.db.Query(r.Context(), `
		SELECT id,COALESCE(ip::text,''),user_agent,created_at,last_seen_at,expires_at
		FROM sessions
		WHERE user_id=$1 AND revoked_at IS NULL AND expires_at>now()
		ORDER BY last_seen_at DESC
	`, p.UserID)
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, ip, userAgent string
		var created, lastSeen, expires time.Time
		if err := rows.Scan(&id, &ip, &userAgent, &created, &lastSeen, &expires); err != nil {
			problem(w, 500, "database error")
			return
		}
		items = append(items, map[string]any{
			"id": id, "ip": ip, "user_agent": userAgent,
			"created_at": created, "last_seen_at": lastSeen, "expires_at": expires,
		})
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) revokeMySession(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(principalKey).(principal)
	id := r.PathValue("id")
	tag, err := s.db.Exec(r.Context(), `
		UPDATE sessions SET revoked_at=now()
		WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL
	`, id, p.UserID)
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	if tag.RowsAffected() == 0 {
		problem(w, 404, "active session not found")
		return
	}
	_ = s.audit(r.Context(), &p.UserID, "SESSION_REVOKED", "session", id, "success", r)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) myApplications(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(principalKey).(principal)
	rows, err := s.db.Query(r.Context(), `
		SELECT DISTINCT a.id,a.name,c.client_id,c.initiate_login_uri
		FROM applications a
		JOIN oauth_clients c ON c.application_id=a.id
		WHERE a.enabled=true AND (
			EXISTS(
				SELECT 1 FROM application_user_assignments ua
				WHERE ua.application_id=a.id AND ua.user_id=$1
			)
			OR EXISTS(
				SELECT 1
				FROM application_group_assignments ga
				JOIN group_memberships gm ON gm.group_id=ga.group_id
				WHERE ga.application_id=a.id AND gm.user_id=$1
			)
		)
		ORDER BY a.name
	`, p.UserID)
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, name, clientID string
		var initiateLoginURI *string
		if err := rows.Scan(&id, &name, &clientID, &initiateLoginURI); err != nil {
			problem(w, 500, "database error")
			return
		}
		items = append(items, map[string]any{
			"id": id, "name": name, "client_id": clientID, "launch_url": initiateLoginURI,
		})
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

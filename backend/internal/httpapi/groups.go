package httpapi

import (
	"net/http"
	"strings"
)

func (s *Server) getGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var name, description string
	if err := s.db.QueryRow(r.Context(), `SELECT name,description FROM groups WHERE id=$1`, id).Scan(&name, &description); err != nil {
		problem(w, 404, "group not found")
		return
	}
	writeJSON(w, 200, map[string]any{"id": id, "name": name, "description": description})
}

func (s *Server) updateGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if decodeJSON(w, r, &in) != nil {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		problem(w, 400, "group name is required")
		return
	}
	tag, err := s.db.Exec(r.Context(), `UPDATE groups SET name=$1,description=$2 WHERE id=$3`, in.Name, strings.TrimSpace(in.Description), id)
	if err != nil {
		problem(w, 409, "group name already exists or update failed")
		return
	}
	if tag.RowsAffected() == 0 {
		problem(w, 404, "group not found")
		return
	}
	p := r.Context().Value(principalKey).(principal)
	_ = s.audit(r.Context(), &p.UserID, "GROUP_UPDATED", "group", id, "success", r)
	writeJSON(w, 200, map[string]any{"id": id, "name": in.Name, "description": strings.TrimSpace(in.Description)})
}

func (s *Server) deleteGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	tag, err := s.db.Exec(r.Context(), `DELETE FROM groups WHERE id=$1`, id)
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	if tag.RowsAffected() == 0 {
		problem(w, 404, "group not found")
		return
	}
	p := r.Context().Value(principalKey).(principal)
	_ = s.audit(r.Context(), &p.UserID, "GROUP_DELETED", "group", id, "success", r)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listGroupMembers(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rows, err := s.db.Query(r.Context(), `
		SELECT u.id,u.username,u.email,u.display_name,u.active,gm.created_at
		FROM group_memberships gm
		JOIN users u ON u.id=gm.user_id
		WHERE gm.group_id=$1
		ORDER BY u.username
	`, id)
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var userID, username, email, displayName string
		var active bool
		var created any
		if err := rows.Scan(&userID, &username, &email, &displayName, &active, &created); err != nil {
			problem(w, 500, "database error")
			return
		}
		items = append(items, map[string]any{
			"id": userID, "username": username, "email": email,
			"display_name": displayName, "active": active, "member_since": created,
		})
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) removeGroupMember(w http.ResponseWriter, r *http.Request) {
	groupID := r.PathValue("id")
	userID := r.PathValue("userId")
	tag, err := s.db.Exec(r.Context(), `DELETE FROM group_memberships WHERE group_id=$1 AND user_id=$2`, groupID, userID)
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	if tag.RowsAffected() == 0 {
		problem(w, 404, "group membership not found")
		return
	}
	p := r.Context().Value(principalKey).(principal)
	_ = s.audit(r.Context(), &p.UserID, "GROUP_MEMBERSHIP_REMOVED", "group", groupID, "success", r)
	w.WriteHeader(http.StatusNoContent)
}

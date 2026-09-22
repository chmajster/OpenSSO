package httpapi

import (
	"net/http"
	"time"
)

func (s *Server) listRoles(w http.ResponseWriter, r *http.Request) {
	rows, e := s.db.Query(r.Context(), "SELECT id,name,description FROM roles ORDER BY name")
	if e != nil {
		problem(w, 500, "database error")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, n, d string
		if rows.Scan(&id, &n, &d) != nil {
			problem(w, 500, "database error")
			return
		}
		items = append(items, map[string]any{"id": id, "name": n, "description": d})
	}
	writeJSON(w, 200, map[string]any{"items": items})
}
func (s *Server) listUserRoles(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("id")
	rows, e := s.db.Query(r.Context(), "SELECT r.id,r.name,r.description FROM role_assignments ra JOIN roles r ON r.id=ra.role_id WHERE ra.user_id=$1 ORDER BY r.name", uid)
	if e != nil {
		problem(w, 500, "database error")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, n, d string
		if rows.Scan(&id, &n, &d) != nil {
			problem(w, 500, "database error")
			return
		}
		items = append(items, map[string]any{"id": id, "name": n, "description": d})
	}
	writeJSON(w, 200, map[string]any{"items": items})
}
func (s *Server) assignRole(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("id")
	var in struct {
		RoleID string `json:"role_id"`
	}
	if decodeJSON(w, r, &in) != nil {
		return
	}
	if _, e := s.db.Exec(r.Context(), "INSERT INTO role_assignments(user_id,role_id) VALUES($1,$2) ON CONFLICT DO NOTHING", uid, in.RoleID); e != nil {
		problem(w, 400, "invalid user or role")
		return
	}
	p := r.Context().Value(principalKey).(principal)
	_ = s.audit(r.Context(), &p.UserID, "ROLE_CHANGED", "user", uid, "success", r)
	writeJSON(w, 200, map[string]any{"user_id": uid, "role_id": in.RoleID, "assigned_at": time.Now().UTC()})
}
func (s *Server) removeRole(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("id")
	rid := r.PathValue("roleId")
	ct, e := s.db.Exec(r.Context(), "DELETE FROM role_assignments WHERE user_id=$1 AND role_id=$2", uid, rid)
	if e != nil {
		problem(w, 500, "database error")
		return
	}
	if ct.RowsAffected() == 0 {
		problem(w, 404, "role assignment not found")
		return
	}
	p := r.Context().Value(principalKey).(principal)
	_ = s.audit(r.Context(), &p.UserID, "ROLE_CHANGED", "user", uid, "success", r)
	w.WriteHeader(204)
}

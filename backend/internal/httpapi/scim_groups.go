package httpapi

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

const scimListSchema = "urn:ietf:params:scim:api:messages:2.0:ListResponse"

func (s *Server) scimResourceTypes(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.scimAuth(r, "users.read"); !ok {
		scimError(w, http.StatusUnauthorized, "invalid or insufficient SCIM bearer token")
		return
	}
	base := strings.TrimRight(s.cfg.PublicURL, "/") + "/scim/v2"
	resources := []map[string]any{
		{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "User", "name": "User", "endpoint": "/Users", "schema": scimUserSchema, "meta": map[string]any{"resourceType": "ResourceType", "location": base + "/ResourceTypes/User"}},
		{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "Group", "name": "Group", "endpoint": "/Groups", "schema": scimGroupSchema, "meta": map[string]any{"resourceType": "ResourceType", "location": base + "/ResourceTypes/Group"}},
	}
	w.Header().Set("Content-Type", "application/scim+json")
	writeJSON(w, http.StatusOK, map[string]any{"schemas": []string{scimListSchema}, "totalResults": len(resources), "startIndex": 1, "itemsPerPage": len(resources), "Resources": resources})
}

func (s *Server) scimSchemas(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.scimAuth(r, "users.read"); !ok {
		scimError(w, http.StatusUnauthorized, "invalid or insufficient SCIM bearer token")
		return
	}
	resources := []map[string]any{
		{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"}, "id": scimUserSchema, "name": "User", "description": "OpenSSO user", "attributes": []map[string]any{
			{"name": "userName", "type": "string", "multiValued": false, "required": true, "uniqueness": "server"},
			{"name": "displayName", "type": "string", "multiValued": false, "required": false},
			{"name": "active", "type": "boolean", "multiValued": false, "required": false},
			{"name": "emails", "type": "complex", "multiValued": true, "required": true},
		}},
		{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"}, "id": scimGroupSchema, "name": "Group", "description": "OpenSSO group", "attributes": []map[string]any{
			{"name": "displayName", "type": "string", "multiValued": false, "required": true, "uniqueness": "server"},
			{"name": "members", "type": "complex", "multiValued": true, "required": false},
		}},
	}
	w.Header().Set("Content-Type", "application/scim+json")
	writeJSON(w, http.StatusOK, map[string]any{"schemas": []string{scimListSchema}, "totalResults": len(resources), "startIndex": 1, "itemsPerPage": len(resources), "Resources": resources})
}

func (s *Server) scimGroups(w http.ResponseWriter, r *http.Request) {
	scope := "groups.read"
	if r.Method == http.MethodPost {
		scope = "groups.write"
	}
	if _, ok := s.scimAuth(r, scope); !ok {
		scimError(w, http.StatusUnauthorized, "invalid or insufficient SCIM bearer token")
		return
	}
	if r.Method == http.MethodPost {
		var in scimGroup
		if decodeJSON(w, r, &in) != nil {
			return
		}
		in.DisplayName = strings.TrimSpace(in.DisplayName)
		if in.DisplayName == "" {
			scimError(w, http.StatusBadRequest, "displayName is required")
			return
		}
		tx, err := s.db.Begin(r.Context())
		if err != nil {
			scimError(w, 500, "database error")
			return
		}
		defer tx.Rollback(r.Context())
		var id string
		if err = tx.QueryRow(r.Context(), "INSERT INTO groups(name) VALUES($1) RETURNING id", in.DisplayName).Scan(&id); err != nil {
			scimError(w, 409, "group displayName already exists")
			return
		}
		if _, err = tx.Exec(r.Context(), "INSERT INTO scim_group_links(group_id,external_id) VALUES($1,NULLIF($2,''))", id, strings.TrimSpace(in.ExternalID)); err != nil {
			scimError(w, 409, "externalId already exists")
			return
		}
		for _, member := range in.Members {
			if strings.TrimSpace(member.Value) == "" {
				continue
			}
			tag, e := tx.Exec(r.Context(), "INSERT INTO group_memberships(group_id,user_id) SELECT $1,id FROM users WHERE id=$2 ON CONFLICT DO NOTHING", id, member.Value)
			if e != nil || tag.RowsAffected() == 0 {
				scimError(w, 400, "group contains an unknown member")
				return
			}
		}
		if err = tx.Commit(r.Context()); err != nil {
			scimError(w, 500, "database error")
			return
		}
		out, err := s.loadSCIMGroup(r, id)
		if err != nil {
			scimError(w, 500, "database error")
			return
		}
		w.Header().Set("Location", fmt.Sprint(out.Meta["location"]))
		w.Header().Set("Content-Type", "application/scim+json")
		writeJSON(w, http.StatusCreated, out)
		return
	}

	start, count := scimPage(r)
	filter := strings.TrimSpace(r.URL.Query().Get("filter"))
	args := []any{}
	where := ""
	if filter != "" {
		parts := strings.SplitN(filter, " eq ", 2)
		if len(parts) != 2 {
			scimError(w, 400, "only eq filters are supported")
			return
		}
		value := strings.Trim(parts[1], " \"")
		switch strings.TrimSpace(parts[0]) {
		case "displayName":
			args = append(args, value)
			where = " WHERE g.name=$1"
		case "externalId":
			args = append(args, value)
			where = " WHERE l.external_id=$1"
		default:
			scimError(w, 400, "unsupported filter attribute")
			return
		}
	}
	var total int
	if err := s.db.QueryRow(r.Context(), "SELECT count(*) FROM groups g LEFT JOIN scim_group_links l ON l.group_id=g.id"+where, args...).Scan(&total); err != nil {
		scimError(w, 500, "database error")
		return
	}
	args = append(args, count, start-1)
	rows, err := s.db.Query(r.Context(), "SELECT g.id FROM groups g LEFT JOIN scim_group_links l ON l.group_id=g.id"+where+fmt.Sprintf(" ORDER BY g.name LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		scimError(w, 500, "database error")
		return
	}
	defer rows.Close()
	resources := []scimGroup{}
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil {
			scimError(w, 500, "database error")
			return
		}
		group, e := s.loadSCIMGroup(r, id)
		if e != nil {
			scimError(w, 500, "database error")
			return
		}
		resources = append(resources, group)
	}
	w.Header().Set("Content-Type", "application/scim+json")
	writeJSON(w, 200, map[string]any{"schemas": []string{scimListSchema}, "totalResults": total, "startIndex": start, "itemsPerPage": len(resources), "Resources": resources})
}

func (s *Server) loadSCIMGroup(r *http.Request, id string) (scimGroup, error) {
	var out scimGroup
	if err := s.db.QueryRow(r.Context(), "SELECT g.id,g.name,COALESCE(l.external_id,'') FROM groups g LEFT JOIN scim_group_links l ON l.group_id=g.id WHERE g.id=$1", id).Scan(&out.ID, &out.DisplayName, &out.ExternalID); err != nil {
		return out, err
	}
	rows, err := s.db.Query(r.Context(), "SELECT u.id,u.display_name FROM group_memberships gm JOIN users u ON u.id=gm.user_id WHERE gm.group_id=$1 ORDER BY u.username", id)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var value, display string
		if err = rows.Scan(&value, &display); err != nil {
			return out, err
		}
		out.Members = append(out.Members, struct {
			Value   string `json:"value"`
			Display string `json:"display,omitempty"`
		}{Value: value, Display: display})
	}
	out.Schemas = []string{scimGroupSchema}
	out.Meta = map[string]any{"resourceType": "Group", "location": strings.TrimRight(s.cfg.PublicURL, "/") + "/scim/v2/Groups/" + id}
	return out, nil
}

func (s *Server) scimGroupResource(w http.ResponseWriter, r *http.Request) {
	scope := "groups.read"
	if r.Method != http.MethodGet {
		scope = "groups.write"
	}
	if _, ok := s.scimAuth(r, scope); !ok {
		scimError(w, http.StatusUnauthorized, "invalid or insufficient SCIM bearer token")
		return
	}
	id := r.PathValue("id")
	if r.Method == http.MethodGet {
		out, err := s.loadSCIMGroup(r, id)
		if err != nil {
			scimError(w, 404, "group not found")
			return
		}
		w.Header().Set("Content-Type", "application/scim+json")
		writeJSON(w, 200, out)
		return
	}
	if r.Method == http.MethodDelete {
		tag, err := s.db.Exec(r.Context(), "DELETE FROM groups WHERE id=$1", id)
		if err != nil || tag.RowsAffected() == 0 {
			scimError(w, 404, "group not found")
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPut {
		scimError(w, 405, "method not allowed")
		return
	}
	var in scimGroup
	if decodeJSON(w, r, &in) != nil {
		return
	}
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	if in.DisplayName == "" {
		scimError(w, 400, "displayName is required")
		return
	}
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		scimError(w, 500, "database error")
		return
	}
	defer tx.Rollback(r.Context())
	tag, err := tx.Exec(r.Context(), "UPDATE groups SET name=$1 WHERE id=$2", in.DisplayName, id)
	if err != nil {
		scimError(w, 409, "group displayName already exists")
		return
	}
	if tag.RowsAffected() == 0 {
		scimError(w, 404, "group not found")
		return
	}
	if _, err = tx.Exec(r.Context(), "INSERT INTO scim_group_links(group_id,external_id) VALUES($1,NULLIF($2,'')) ON CONFLICT(group_id) DO UPDATE SET external_id=EXCLUDED.external_id", id, strings.TrimSpace(in.ExternalID)); err != nil {
		scimError(w, 409, "externalId already exists")
		return
	}
	if _, err = tx.Exec(r.Context(), "DELETE FROM group_memberships WHERE group_id=$1", id); err != nil {
		scimError(w, 500, "database error")
		return
	}
	for _, member := range in.Members {
		if strings.TrimSpace(member.Value) == "" {
			continue
		}
		tag, e := tx.Exec(r.Context(), "INSERT INTO group_memberships(group_id,user_id) SELECT $1,id FROM users WHERE id=$2 ON CONFLICT DO NOTHING", id, member.Value)
		if e != nil || tag.RowsAffected() == 0 {
			scimError(w, 400, "group contains an unknown member")
			return
		}
	}
	if err = tx.Commit(r.Context()); err != nil {
		scimError(w, 500, "database error")
		return
	}
	out, err := s.loadSCIMGroup(r, id)
	if err != nil {
		scimError(w, 500, "database error")
		return
	}
	w.Header().Set("Content-Type", "application/scim+json")
	writeJSON(w, 200, out)
}

func parseSCIMPositiveInt(value string, fallback int) int {
	n, err := strconv.Atoi(value)
	if err != nil || n < 1 {
		return fallback
	}
	return n
}

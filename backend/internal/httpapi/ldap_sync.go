package httpapi

import (
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func (s *Server) syncLDAPProvider(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p, secret, err := s.loadLDAPProvider(r.Context(), id)
	if err != nil {
		problem(w, 404, "LDAP provider not found")
		return
	}
	conn, err := s.ldapServiceConnection(r.Context(), p, secret)
	if err != nil {
		s.recordLDAPSync(r, id, "failure", err.Error())
		problem(w, 502, "LDAP connection or bind failed")
		return
	}
	defer conn.Close()
	req := ldap.NewSearchRequest(p.UserBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 30, false, "(objectClass=person)", []string{p.UserIDAttribute, p.UsernameAttribute, p.EmailAttribute, p.DisplayNameAttribute}, nil)
	res, err := conn.SearchWithPaging(req, 500)
	if err != nil {
		s.recordLDAPSync(r, id, "failure", err.Error())
		problem(w, 502, "LDAP user synchronization search failed")
		return
	}
	seen := map[string]bool{}
	synced, skipped := 0, 0
	for _, e := range res.Entries {
		identity := ldapIdentity{
			DN: e.DN,
			Username: strings.ToLower(strings.TrimSpace(e.GetAttributeValue(p.UsernameAttribute))),
			Email: strings.ToLower(strings.TrimSpace(e.GetAttributeValue(p.EmailAttribute))),
			DisplayName: strings.TrimSpace(e.GetAttributeValue(p.DisplayNameAttribute)),
		}
		raw := e.GetRawAttributeValue(p.UserIDAttribute)
		identity.ExternalID = e.GetAttributeValue(p.UserIDAttribute)
		if len(raw) > 0 { identity.ExternalID = base64.RawURLEncoding.EncodeToString(raw) }
		if identity.ExternalID == "" || identity.Username == "" || !strings.Contains(identity.Email, "@") { skipped++; continue }
		if _, _, err = s.upsertLDAPIdentity(r.Context(), id, identity); err != nil { skipped++; continue }
		seen[identity.ExternalID] = true
		synced++
	}
	var disabled int64
	if len(seen) > 0 {
		rows, qerr := s.db.Query(r.Context(), "SELECT external_id,user_id FROM ldap_identity_links WHERE provider_id=$1", id)
		if qerr == nil {
			defer rows.Close()
			for rows.Next() {
				var external, userID string
				if rows.Scan(&external, &userID) == nil && !seen[external] {
					tag, _ := s.db.Exec(r.Context(), "UPDATE users SET active=false,updated_at=now() WHERE id=$1 AND NOT EXISTS(SELECT 1 FROM password_credentials WHERE user_id=$1)", userID)
					disabled += tag.RowsAffected()
				}
			}
		}
	}
	s.recordLDAPSync(r, id, "success", "")
	pr := r.Context().Value(principalKey).(principal)
	_ = s.audit(r.Context(), &pr.UserID, "LDAP_SYNC", "ldap_provider", id, "success", r)
	writeJSON(w, 200, map[string]any{"synchronized": synced, "skipped": skipped, "disabled_missing": disabled, "completed_at": time.Now().UTC()})
}

func (s *Server) recordLDAPSync(r *http.Request, id, result, detail string) {
	if len(detail) > 1000 { detail = detail[:1000] }
	_, _ = s.db.Exec(r.Context(), "UPDATE ldap_providers SET last_sync_at=now(),last_sync_result=$2,last_sync_error=$3 WHERE id=$1", id, result, detail)
}

package httpapi

import (
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/chmajster/OpenSSO/backend/internal/security"
)

type securityPolicy struct {
	PasswordMinLength    int  `json:"password_min_length"`
	PasswordRequireUpper bool `json:"password_require_upper"`
	PasswordRequireLower bool `json:"password_require_lower"`
	PasswordRequireDigit bool `json:"password_require_digit"`
	PasswordRequireSymbol bool `json:"password_require_symbol"`
	LockoutThreshold     int  `json:"lockout_threshold"`
	LockoutMinutes       int  `json:"lockout_minutes"`
	SessionTTLMinutes    int  `json:"session_ttl_minutes"`
}

func (s *Server) getSecurityPolicy(r *http.Request) (securityPolicy, error) {
	var p securityPolicy
	err := s.db.QueryRow(r.Context(), `
		SELECT password_min_length,password_require_upper,password_require_lower,password_require_digit,password_require_symbol,
		       lockout_threshold,lockout_minutes,session_ttl_minutes
		FROM security_policies WHERE id=1
	`).Scan(
		&p.PasswordMinLength, &p.PasswordRequireUpper, &p.PasswordRequireLower, &p.PasswordRequireDigit, &p.PasswordRequireSymbol,
		&p.LockoutThreshold, &p.LockoutMinutes, &p.SessionTTLMinutes,
	)
	return p, err
}

func (s *Server) securityPolicy(w http.ResponseWriter, r *http.Request) {
	p, err := s.getSecurityPolicy(r)
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	writeJSON(w, 200, p)
}

func (s *Server) updateSecurityPolicy(w http.ResponseWriter, r *http.Request) {
	var in securityPolicy
	if decodeJSON(w, r, &in) != nil {
		return
	}
	if in.PasswordMinLength < 12 || in.PasswordMinLength > 128 ||
		in.LockoutThreshold < 3 || in.LockoutThreshold > 100 ||
		in.LockoutMinutes < 1 || in.LockoutMinutes > 1440 ||
		in.SessionTTLMinutes < 5 || in.SessionTTLMinutes > 10080 {
		problem(w, 400, "invalid security policy values")
		return
	}
	_, err := s.db.Exec(r.Context(), `
		UPDATE security_policies
		SET password_min_length=$1,password_require_upper=$2,password_require_lower=$3,password_require_digit=$4,password_require_symbol=$5,
		    lockout_threshold=$6,lockout_minutes=$7,session_ttl_minutes=$8,updated_at=now()
		WHERE id=1
	`, in.PasswordMinLength, in.PasswordRequireUpper, in.PasswordRequireLower, in.PasswordRequireDigit, in.PasswordRequireSymbol,
		in.LockoutThreshold, in.LockoutMinutes, in.SessionTTLMinutes)
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	p := r.Context().Value(principalKey).(principal)
	_ = s.audit(r.Context(), &p.UserID, "POLICY_CHANGED", "security_policy", "1", "success", r)
	writeJSON(w, 200, in)
}

func passwordPolicyViolation(policy securityPolicy, password string) string {
	if len([]rune(password)) < policy.PasswordMinLength {
		return "password does not meet current minimum length"
	}
	var upper, lower, digit, symbol bool
	for _, r := range password {
		upper = upper || unicode.IsUpper(r)
		lower = lower || unicode.IsLower(r)
		digit = digit || unicode.IsDigit(r)
		symbol = symbol || unicode.IsPunct(r) || unicode.IsSymbol(r)
	}
	if policy.PasswordRequireUpper && !upper {
		return "password must contain an uppercase letter"
	}
	if policy.PasswordRequireLower && !lower {
		return "password must contain a lowercase letter"
	}
	if policy.PasswordRequireDigit && !digit {
		return "password must contain a digit"
	}
	if policy.PasswordRequireSymbol && !symbol {
		return "password must contain a symbol"
	}
	return ""
}

func (s *Server) getUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var out struct {
		ID                 string     `json:"id"`
		Username           string     `json:"username"`
		Email              string     `json:"email"`
		DisplayName        string     `json:"display_name"`
		Active             bool       `json:"active"`
		MustChangePassword bool       `json:"must_change_password"`
		LockedUntil        *time.Time `json:"locked_until"`
		CreatedAt          time.Time  `json:"created_at"`
	}
	err := s.db.QueryRow(r.Context(), `
		SELECT id,username,email,display_name,active,must_change_password,locked_until,created_at
		FROM users WHERE id=$1
	`, id).Scan(&out.ID, &out.Username, &out.Email, &out.DisplayName, &out.Active, &out.MustChangePassword, &out.LockedUntil, &out.CreatedAt)
	if err != nil {
		problem(w, 404, "user not found")
		return
	}
	writeJSON(w, 200, out)
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in struct {
		Email       string `json:"email"`
		DisplayName string `json:"display_name"`
		Active      *bool  `json:"active"`
	}
	if decodeJSON(w, r, &in) != nil {
		return
	}
	if !strings.Contains(strings.TrimSpace(in.Email), "@") {
		problem(w, 400, "invalid email")
		return
	}
	if in.Active == nil {
		problem(w, 400, "active is required")
		return
	}
	tag, err := s.db.Exec(r.Context(), `
		UPDATE users SET email=lower($1),display_name=$2,active=$3,updated_at=now()
		WHERE id=$4
	`, strings.TrimSpace(in.Email), strings.TrimSpace(in.DisplayName), *in.Active, id)
	if err != nil {
		problem(w, 409, "email already exists or user update failed")
		return
	}
	if tag.RowsAffected() == 0 {
		problem(w, 404, "user not found")
		return
	}
	if !*in.Active {
		_, _ = s.db.Exec(r.Context(), `UPDATE sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL`, id)
	}
	p := r.Context().Value(principalKey).(principal)
	_ = s.audit(r.Context(), &p.UserID, "USER_UPDATED", "user", id, "success", r)
	writeJSON(w, 200, map[string]any{"id": id, "active": *in.Active})
}

func (s *Server) unlockUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	tag, err := s.db.Exec(r.Context(), `UPDATE users SET failed_logins=0,locked_until=NULL,updated_at=now() WHERE id=$1`, id)
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	if tag.RowsAffected() == 0 {
		problem(w, 404, "user not found")
		return
	}
	p := r.Context().Value(principalKey).(principal)
	_ = s.audit(r.Context(), &p.UserID, "USER_UNLOCKED", "user", id, "success", r)
	w.WriteHeader(204)
}

func (s *Server) resetUserPassword(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in struct {
		Password string `json:"password"`
	}
	if decodeJSON(w, r, &in) != nil {
		return
	}
	policy, err := s.getSecurityPolicy(r)
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	if violation := passwordPolicyViolation(policy, in.Password); violation != "" {
		problem(w, 400, violation)
		return
	}
	hash, err := security.HashPassword(in.Password)
	if err != nil {
		problem(w, 400, err.Error())
		return
	}
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	defer tx.Rollback(r.Context())
	tag, err := tx.Exec(r.Context(), `UPDATE password_credentials SET password_hash=$1,changed_at=now() WHERE user_id=$2`, hash, id)
	if err != nil || tag.RowsAffected() == 0 {
		problem(w, 404, "user not found")
		return
	}
	if _, err = tx.Exec(r.Context(), `UPDATE users SET must_change_password=true,failed_logins=0,locked_until=NULL,updated_at=now() WHERE id=$1`, id); err != nil {
		problem(w, 500, "database error")
		return
	}
	if _, err = tx.Exec(r.Context(), `UPDATE sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL`, id); err != nil {
		problem(w, 500, "database error")
		return
	}
	actor := r.Context().Value(principalKey).(principal)
	if err = s.auditTx(r.Context(), tx, &actor.UserID, "PASSWORD_RESET", "user", id, "success", r); err != nil {
		problem(w, 500, "audit error")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		problem(w, 500, "database error")
		return
	}
	w.WriteHeader(204)
}

func (s *Server) changeOwnPassword(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(principalKey).(principal)
	var in struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if decodeJSON(w, r, &in) != nil {
		return
	}
	var currentHash string
	if err := s.db.QueryRow(r.Context(), `SELECT password_hash FROM password_credentials WHERE user_id=$1`, p.UserID).Scan(&currentHash); err != nil {
		problem(w, 500, "database error")
		return
	}
	if !security.VerifyPassword(currentHash, in.CurrentPassword) {
		problem(w, 401, "current password is invalid")
		return
	}
	policy, err := s.getSecurityPolicy(r)
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	if violation := passwordPolicyViolation(policy, in.NewPassword); violation != "" {
		problem(w, 400, violation)
		return
	}
	if security.VerifyPassword(currentHash, in.NewPassword) {
		problem(w, 400, "new password must differ from current password")
		return
	}
	newHash, err := security.HashPassword(in.NewPassword)
	if err != nil {
		problem(w, 400, err.Error())
		return
	}
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	defer tx.Rollback(r.Context())
	if _, err = tx.Exec(r.Context(), `UPDATE password_credentials SET password_hash=$1,changed_at=now() WHERE user_id=$2`, newHash, p.UserID); err != nil {
		problem(w, 500, "database error")
		return
	}
	if _, err = tx.Exec(r.Context(), `UPDATE users SET must_change_password=false,updated_at=now() WHERE id=$1`, p.UserID); err != nil {
		problem(w, 500, "database error")
		return
	}
	if err = s.auditTx(r.Context(), tx, &p.UserID, "PASSWORD_CHANGED", "user", p.UserID, "success", r); err != nil {
		problem(w, 500, "audit error")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		problem(w, 500, "database error")
		return
	}
	w.WriteHeader(204)
}

func (s *Server) listSessions(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query(r.Context(), `
		SELECT s.id,s.user_id,u.username,COALESCE(s.ip::text,''),s.user_agent,s.created_at,s.last_seen_at,s.expires_at
		FROM sessions s JOIN users u ON u.id=s.user_id
		WHERE s.revoked_at IS NULL AND s.expires_at>now()
		ORDER BY s.last_seen_at DESC LIMIT 1000
	`)
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, uid, username, ip, ua string
		var created, lastSeen, expires time.Time
		if err := rows.Scan(&id, &uid, &username, &ip, &ua, &created, &lastSeen, &expires); err != nil {
			problem(w, 500, "database error")
			return
		}
		items = append(items, map[string]any{
			"id": id, "user_id": uid, "username": username, "ip": ip, "user_agent": ua,
			"created_at": created, "last_seen_at": lastSeen, "expires_at": expires,
		})
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) revokeSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	tag, err := s.db.Exec(r.Context(), `UPDATE sessions SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL`, id)
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	if tag.RowsAffected() == 0 {
		problem(w, 404, "active session not found")
		return
	}
	p := r.Context().Value(principalKey).(principal)
	_ = s.audit(r.Context(), &p.UserID, "SESSION_REVOKED", "session", id, "success", r)
	w.WriteHeader(204)
}

func (s *Server) revokeUserSessions(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := s.db.Exec(r.Context(), `UPDATE sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL`, id); err != nil {
		problem(w, 500, "database error")
		return
	}
	p := r.Context().Value(principalKey).(principal)
	_ = s.audit(r.Context(), &p.UserID, "SESSION_REVOKED", "user", id, "success", r)
	w.WriteHeader(204)
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	var users, activeUsers, lockedUsers, applications, sessions, logins24h, failed24h int64
	err := s.db.QueryRow(r.Context(), `
		SELECT
		  (SELECT count(*) FROM users),
		  (SELECT count(*) FROM users WHERE active=true),
		  (SELECT count(*) FROM users WHERE locked_until>now()),
		  (SELECT count(*) FROM applications WHERE enabled=true),
		  (SELECT count(*) FROM sessions WHERE revoked_at IS NULL AND expires_at>now()),
		  (SELECT count(*) FROM audit_events WHERE event='LOGIN_SUCCESS' AND occurred_at>now()-interval '24 hours'),
		  (SELECT count(*) FROM audit_events WHERE event='LOGIN_FAILED' AND occurred_at>now()-interval '24 hours')
	`).Scan(&users, &activeUsers, &lockedUsers, &applications, &sessions, &logins24h, &failed24h)
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	writeJSON(w, 200, map[string]any{
		"users":             users,
		"active_users":      activeUsers,
		"locked_users":      lockedUsers,
		"applications":      applications,
		"active_sessions":   sessions,
		"logins_24h":        logins24h,
		"failed_logins_24h": failed24h,
	})
}

func (s *Server) revokeAllSessions(w http.ResponseWriter, r *http.Request) {
	tag, err := s.db.Exec(r.Context(), `
		UPDATE sessions SET revoked_at=now()
		WHERE revoked_at IS NULL AND expires_at>now()
	`)
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	p := r.Context().Value(principalKey).(principal)
	_ = s.audit(r.Context(), &p.UserID, "SESSION_REVOKED", "global", "", "success", r)
	writeJSON(w, 200, map[string]any{"revoked_sessions": tag.RowsAffected()})
}

package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/chmajster/OpenSSO/backend/internal/config"
	"github.com/chmajster/OpenSSO/backend/internal/mfa"
	"github.com/chmajster/OpenSSO/backend/internal/oidc"
	"github.com/chmajster/OpenSSO/backend/internal/samlidp"
	"github.com/chmajster/OpenSSO/backend/internal/security"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

type Server struct {
	cfg   config.Config
	db    *pgxpool.Pool
	redis *redis.Client
	log   *slog.Logger
	keys  *oidc.KeyManager
	mfa   *mfa.Service
	saml  *samlidp.Runtime
}
type principal struct {
	SessionID          string
	UserID             string
	Username           string
	MustChangePassword bool
	MFAVerified        bool
}
type contextKey string

const principalKey contextKey = "principal"
const requestIDKey contextKey = "request_id"

func New(cfg config.Config, db *pgxpool.Pool, rdb *redis.Client, log *slog.Logger, keys *oidc.KeyManager, mfaService *mfa.Service, saml *samlidp.Runtime) *Server {
	return &Server{cfg: cfg, db: db, redis: rdb, log: log, keys: keys, mfa: mfaService, saml: saml}
}

func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /health/live", s.live)
	m.HandleFunc("GET /health/ready", s.ready)
	m.HandleFunc("GET /.well-known/openid-configuration", s.oidcDiscovery)
	m.HandleFunc("GET /.well-known/oauth-authorization-server", s.oauthAuthorizationServerMetadata)
	m.HandleFunc("GET /.well-known/jwks.json", s.jwks)
	m.HandleFunc("GET /oauth2/authorize", s.authorize)
	m.HandleFunc("POST /oauth2/authorize/consent", s.authorizeConsent)
	m.HandleFunc("POST /oauth2/token", s.tokenEndpoint)
	m.HandleFunc("POST /oauth2/revoke", s.revokeToken)
	m.HandleFunc("POST /oauth2/introspect", s.introspectToken)
	m.HandleFunc("GET /userinfo", s.userinfo)
	m.HandleFunc("GET /oauth2/logout", s.oauthLogout)
	m.HandleFunc("POST /oauth2/logout", s.oauthLogout)
	if s.saml != nil {
		m.Handle("/saml/", s.saml.Handler())
	}
	m.HandleFunc("GET /api/v1/setup/status", s.setupStatus)
	m.HandleFunc("POST /api/v1/setup/bootstrap", s.bootstrap)
	m.HandleFunc("POST /api/v1/auth/login", s.login)
	m.HandleFunc("POST /api/v1/auth/logout", s.withPrincipalRaw(s.logout))
	m.HandleFunc("POST /api/v1/auth/mfa/verify", s.withPrincipalRaw(s.verifyMFAFactor))
	m.HandleFunc("POST /api/v1/auth/mfa/webauthn/begin", s.withPrincipalRaw(s.beginWebAuthnAuthentication))
	m.HandleFunc("POST /api/v1/auth/mfa/webauthn/finish", s.withPrincipalRaw(s.finishWebAuthnAuthentication))
	m.HandleFunc("GET /api/v1/me", s.withPrincipalRaw(s.me))
	m.HandleFunc("GET /api/v1/me/mfa/status", s.withPrincipalRaw(s.myMFAStatus))
	m.HandleFunc("POST /api/v1/me/mfa/totp/begin", s.withPrincipalRaw(s.beginTOTPEnrollment))
	m.HandleFunc("POST /api/v1/me/mfa/totp/confirm", s.withPrincipalRaw(s.confirmTOTPEnrollment))
	m.HandleFunc("DELETE /api/v1/me/mfa/totp", s.withPrincipalRaw(s.disableTOTP))
	m.HandleFunc("POST /api/v1/me/mfa/recovery/regenerate", s.withPrincipalRaw(s.regenerateRecoveryCodes))
	m.HandleFunc("POST /api/v1/me/mfa/webauthn/register/begin", s.withPrincipalRaw(s.beginWebAuthnRegistration))
	m.HandleFunc("POST /api/v1/me/mfa/webauthn/register/finish", s.withPrincipalRaw(s.finishWebAuthnRegistration))
	m.HandleFunc("DELETE /api/v1/me/mfa/webauthn/{id}", s.withPrincipalRaw(s.deleteWebAuthnCredential))
	m.HandleFunc("GET /api/v1/me/access", s.withPrincipal(s.myAccess))
	m.HandleFunc("GET /api/v1/me/profile", s.withPrincipal(s.myProfile))
	m.HandleFunc("PATCH /api/v1/me/profile", s.withPrincipal(s.updateMyProfile))
	m.HandleFunc("POST /api/v1/me/password", s.withPrincipalRaw(s.changeOwnPassword))
	m.HandleFunc("GET /api/v1/me/applications", s.withPrincipal(s.myApplications))
	m.HandleFunc("GET /api/v1/me/sessions", s.withPrincipal(s.mySessions))
	m.HandleFunc("DELETE /api/v1/me/sessions/{id}", s.withPrincipal(s.revokeMySession))
	m.HandleFunc("GET /api/v1/dashboard", s.require("users.read", s.dashboard))
	m.HandleFunc("GET /api/v1/users", s.require("users.read", s.listUsers))
	m.HandleFunc("POST /api/v1/users", s.require("users.write", s.createUser))
	m.HandleFunc("GET /api/v1/users/{id}", s.require("users.read", s.getUser))
	m.HandleFunc("PATCH /api/v1/users/{id}", s.require("users.write", s.updateUser))
	m.HandleFunc("POST /api/v1/users/{id}/unlock", s.require("users.write", s.unlockUser))
	m.HandleFunc("POST /api/v1/users/{id}/reset-password", s.require("users.write", s.resetUserPassword))
	m.HandleFunc("POST /api/v1/users/{id}/sessions/revoke-all", s.require("sessions.write", s.revokeUserSessions))
	m.HandleFunc("GET /api/v1/users/{id}/mfa", s.require("mfa.read", s.adminUserMFAStatus))
	m.HandleFunc("POST /api/v1/users/{id}/mfa/reset", s.require("mfa.write", s.resetUserMFA))
	m.HandleFunc("GET /api/v1/groups", s.require("groups.read", s.listGroups))
	m.HandleFunc("POST /api/v1/groups", s.require("groups.write", s.createGroup))
	m.HandleFunc("GET /api/v1/groups/{id}", s.require("groups.read", s.getGroup))
	m.HandleFunc("PATCH /api/v1/groups/{id}", s.require("groups.write", s.updateGroup))
	m.HandleFunc("DELETE /api/v1/groups/{id}", s.require("groups.write", s.deleteGroup))
	m.HandleFunc("GET /api/v1/groups/{id}/members", s.require("groups.read", s.listGroupMembers))
	m.HandleFunc("POST /api/v1/groups/{id}/members", s.require("groups.write", s.addGroupMember))
	m.HandleFunc("DELETE /api/v1/groups/{id}/members/{userId}", s.require("groups.write", s.removeGroupMember))
	m.HandleFunc("GET /api/v1/groups/{id}/mfa-policy", s.require("mfa.read", s.groupMFAPolicy))
	m.HandleFunc("PUT /api/v1/groups/{id}/mfa-policy", s.require("mfa.write", s.updateGroupMFAPolicy))
	m.HandleFunc("GET /api/v1/applications", s.require("applications.read", s.listApplications))
	m.HandleFunc("POST /api/v1/applications", s.require("applications.write", s.createApplication))
	m.HandleFunc("GET /api/v1/applications/{id}/integration", s.require("applications.read", s.applicationIntegration))
	m.HandleFunc("PUT /api/v1/applications/{id}", s.require("applications.write", s.updateApplication))
	m.HandleFunc("POST /api/v1/applications/{id}/rotate-secret", s.require("applications.write", s.rotateClientSecret))
	m.HandleFunc("GET /api/v1/applications/{id}/assignments", s.require("applications.read", s.applicationAssignments))
	m.HandleFunc("POST /api/v1/applications/{id}/assign/users", s.require("applications.write", s.assignApplicationUser))
	m.HandleFunc("DELETE /api/v1/applications/{id}/assign/users/{userId}", s.require("applications.write", s.removeApplicationUser))
	m.HandleFunc("POST /api/v1/applications/{id}/assign/groups", s.require("applications.write", s.assignApplicationGroup))
	m.HandleFunc("DELETE /api/v1/applications/{id}/assign/groups/{groupId}", s.require("applications.write", s.removeApplicationGroup))
	m.HandleFunc("GET /api/v1/applications/{id}/mfa-policy", s.require("mfa.read", s.applicationMFAPolicy))
	m.HandleFunc("PUT /api/v1/applications/{id}/mfa-policy", s.require("mfa.write", s.updateApplicationMFAPolicy))
	m.HandleFunc("GET /api/v1/audit", s.require("audit.read", s.listAudit))
	m.HandleFunc("GET /api/v1/roles", s.require("users.read", s.listRoles))
	m.HandleFunc("GET /api/v1/users/{id}/roles", s.require("users.read", s.listUserRoles))
	m.HandleFunc("POST /api/v1/users/{id}/roles", s.require("rbac.write", s.assignRole))
	m.HandleFunc("DELETE /api/v1/users/{id}/roles/{roleId}", s.require("rbac.write", s.removeRole))
	m.HandleFunc("GET /api/v1/sessions", s.require("sessions.read", s.listSessions))
	m.HandleFunc("DELETE /api/v1/sessions/{id}", s.require("sessions.write", s.revokeSession))
	m.HandleFunc("POST /api/v1/sessions/revoke-all", s.require("sessions.write", s.revokeAllSessions))
	m.HandleFunc("GET /api/v1/security/policy", s.require("policies.read", s.securityPolicy))
	m.HandleFunc("PUT /api/v1/security/policy", s.require("policies.write", s.updateSecurityPolicy))
	m.HandleFunc("GET /api/v1/signing-keys", s.require("signing_keys.read", s.listSigningKeys))
	m.HandleFunc("POST /api/v1/signing-keys/rotate", s.require("signing_keys.rotate", s.rotateSigningKey))
	m.HandleFunc("POST /api/v1/saml/applications", s.require("saml.write", s.createSAMLApplication))
	m.HandleFunc("PUT /api/v1/saml/applications/{id}", s.require("saml.write", s.updateSAMLApplication))
	m.HandleFunc("GET /api/v1/saml/applications/{id}/integration", s.require("saml.read", s.samlApplicationIntegration))
	m.HandleFunc("GET /api/v1/saml/certificates", s.require("saml.read", s.samlCertificates))
	m.HandleFunc("POST /api/v1/saml/certificates/rotate", s.require("saml.rotate", s.rotateSAMLCertificate))
	m.HandleFunc("POST /api/v1/saml/continue", s.withPrincipal(s.continueSAML))
	return s.middleware(m)
}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.cfg.TrustProxyHeaders {
			r.Header.Del("X-Forwarded-For")
			r.Header.Del("X-Real-IP")
		}
		rid, _ := security.RandomToken(12)
		w.Header().Set("X-Request-ID", rid)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		if !strings.HasPrefix(r.URL.Path, "/health/") {
			expected, err := url.Parse(s.cfg.PublicURL)
			if err != nil || expected.Host == "" {
				problem(w, 500, "invalid public URL configuration")
				return
			}
			if !strings.EqualFold(r.Host, expected.Host) {
				problem(w, 400, "invalid host")
				return
			}
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/") && r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS" && r.URL.Path != "/api/v1/auth/login" && r.URL.Path != "/api/v1/setup/bootstrap" {
			cookie, err := r.Cookie("opensso_csrf")
			header := r.Header.Get("X-CSRF-Token")
			if err != nil || header == "" || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(header)) != 1 {
				problem(w, 403, "CSRF validation failed")
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey, rid)))
	})
}
func (s *Server) live(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]string{"status": "ok"})
}
func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if e := s.db.Ping(ctx); e != nil {
		problem(w, 503, "database unavailable")
		return
	}
	if e := s.redis.Ping(ctx).Err(); e != nil {
		problem(w, 503, "redis unavailable")
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ready"})
}
func (s *Server) setupStatus(w http.ResponseWriter, r *http.Request) {
	var initialized bool
	if e := s.db.QueryRow(r.Context(), "SELECT initialized FROM system_state WHERE id=1").Scan(&initialized); e != nil {
		problem(w, 500, "database error")
		return
	}
	writeJSON(w, 200, map[string]bool{"initialized": initialized})
}
func (s *Server) bootstrap(w http.ResponseWriter, r *http.Request) {
	if s.cfg.BootstrapToken == "" {
		problem(w, 403, "bootstrap is disabled")
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+s.cfg.BootstrapToken {
		problem(w, 403, "invalid bootstrap credential")
		return
	}
	var in struct {
		Username    string `json:"username"`
		Email       string `json:"email"`
		DisplayName string `json:"display_name"`
		Password    string `json:"password"`
	}
	if decodeJSON(w, r, &in) != nil {
		return
	}
	in.Username = strings.ToLower(strings.TrimSpace(in.Username))
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	if len(in.Username) < 3 || !strings.Contains(in.Email, "@") {
		problem(w, 400, "invalid username or email")
		return
	}
	policy, e := s.getSecurityPolicy(r)
	if e != nil {
		problem(w, 500, "database error")
		return
	}
	if violation := passwordPolicyViolation(policy, in.Password); violation != "" {
		problem(w, 400, violation)
		return
	}
	hash, e := security.HashPassword(in.Password)
	if e != nil {
		problem(w, 400, e.Error())
		return
	}
	tx, e := s.db.Begin(r.Context())
	if e != nil {
		problem(w, 500, "database error")
		return
	}
	defer tx.Rollback(r.Context())
	var initialized bool
	if e = tx.QueryRow(r.Context(), "SELECT initialized FROM system_state WHERE id=1 FOR UPDATE").Scan(&initialized); e != nil || initialized {
		problem(w, 409, "installation already initialized")
		return
	}
	var uid string
	if e = tx.QueryRow(r.Context(), "INSERT INTO users(username,email,display_name) VALUES($1,$2,$3) RETURNING id", in.Username, in.Email, strings.TrimSpace(in.DisplayName)).Scan(&uid); e != nil {
		problem(w, 409, "username or email already exists")
		return
	}
	if _, e = tx.Exec(r.Context(), "INSERT INTO password_credentials(user_id,password_hash) VALUES($1,$2)", uid, hash); e != nil {
		problem(w, 500, "database error")
		return
	}
	if _, e = tx.Exec(r.Context(), "INSERT INTO role_assignments(user_id,role_id) SELECT $1,id FROM roles WHERE name='Super Admin'", uid); e != nil {
		problem(w, 500, "database error")
		return
	}
	if _, e = tx.Exec(r.Context(), "UPDATE system_state SET initialized=true,initialized_at=now() WHERE id=1"); e != nil {
		problem(w, 500, "database error")
		return
	}
	if e = s.auditTx(r.Context(), tx, &uid, "USER_CREATED", "user", uid, "success", r); e != nil {
		problem(w, 500, "audit error")
		return
	}
	if e = tx.Commit(r.Context()); e != nil {
		problem(w, 500, "database error")
		return
	}
	writeJSON(w, 201, map[string]string{"user_id": uid})
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.allowLogin(r.Context(), ip) {
		problem(w, 429, "too many login attempts")
		return
	}
	policy, policyErr := s.getSecurityPolicy(r)
	if policyErr != nil {
		problem(w, 500, "database error")
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if decodeJSON(w, r, &in) != nil {
		return
	}
	var uid, username, hash string
	var active bool
	var locked *time.Time
	e := s.db.QueryRow(r.Context(), "SELECT u.id,u.username,u.active,u.locked_until,p.password_hash FROM users u JOIN password_credentials p ON p.user_id=u.id WHERE lower(u.username)=lower($1) OR lower(u.email)=lower($1)", strings.TrimSpace(in.Username)).Scan(&uid, &username, &active, &locked, &hash)
	valid := e == nil && active && (locked == nil || locked.Before(time.Now())) && security.VerifyPassword(hash, in.Password)
	if !valid {
		if e == nil {
			_, _ = s.db.Exec(r.Context(), "UPDATE users SET failed_logins=failed_logins+1,locked_until=CASE WHEN failed_logins+1 >= $2 THEN now()+make_interval(mins => $3) ELSE locked_until END WHERE id=$1", uid, policy.LockoutThreshold, policy.LockoutMinutes)
		}
		_ = s.audit(r.Context(), nil, "LOGIN_FAILED", "user", uid, "failure", r)
		problem(w, 401, "invalid credentials")
		return
	}

	mfaStatus, e := s.mfa.Status(r.Context(), uid, nil)
	if e != nil {
		problem(w, 500, "MFA policy lookup failed")
		return
	}

	token, e := security.RandomToken(32)
	if e != nil {
		problem(w, 500, "entropy failure")
		return
	}
	expires := time.Now().Add(time.Duration(policy.SessionTTLMinutes) * time.Minute)
	var sessionID string
	if e = s.db.QueryRow(r.Context(), "INSERT INTO sessions(user_id,token_hash,ip,user_agent,expires_at) VALUES($1,$2,$3,$4,$5) RETURNING id", uid, security.SHA256String(token), nullableIP(ip), truncate(r.UserAgent(), 512), expires).Scan(&sessionID); e != nil {
		problem(w, 500, "database error")
		return
	}
	_, _ = s.db.Exec(r.Context(), "UPDATE users SET failed_logins=0,locked_until=NULL WHERE id=$1", uid)
	if mfaStatus.Required {
		_ = s.audit(r.Context(), &uid, "LOGIN_PRIMARY_SUCCESS", "user", uid, "success", r)
	} else {
		_ = s.audit(r.Context(), &uid, "LOGIN_SUCCESS", "user", uid, "success", r)
	}

	csrf, e := security.RandomToken(24)
	if e != nil {
		problem(w, 500, "entropy failure")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "opensso_session", Value: token, Path: "/", HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode, Expires: expires})
	http.SetCookie(w, &http.Cookie{Name: "opensso_csrf", Value: csrf, Path: "/", HttpOnly: false, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode, Expires: expires})
	writeJSON(w, 200, map[string]any{
		"user_id":                 uid,
		"username":                username,
		"session_id":              sessionID,
		"expires_at":              expires,
		"mfa_required":            mfaStatus.Required,
		"mfa_enrollment_required": mfaStatus.Required && !mfaStatus.HasPrimaryFactor,
	})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, e := r.Cookie("opensso_session"); e == nil {
		_, _ = s.db.Exec(r.Context(), "UPDATE sessions SET revoked_at=now() WHERE token_hash=$1 AND revoked_at IS NULL", security.SHA256String(c.Value))
	}
	p := r.Context().Value(principalKey).(principal)
	_ = s.audit(r.Context(), &p.UserID, "LOGOUT", "user", p.UserID, "success", r)
	http.SetCookie(w, &http.Cookie{Name: "opensso_session", Value: "", Path: "/", HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "opensso_csrf", Value: "", Path: "/", HttpOnly: false, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(principalKey).(principal)
	status, err := s.mfa.Status(r.Context(), p.UserID, nil)
	if err != nil {
		problem(w, 500, "MFA status lookup failed")
		return
	}
	writeJSON(w, 200, map[string]any{
		"session_id":              p.SessionID,
		"user_id":                 p.UserID,
		"username":                p.Username,
		"must_change_password":    p.MustChangePassword,
		"mfa_verified":            p.MFAVerified,
		"mfa_required":            status.Required,
		"mfa_enrollment_required": status.Required && !status.HasPrimaryFactor,
	})
}

func (s *Server) withPrincipalRaw(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("opensso_session")
		if err != nil {
			problem(w, 401, "authentication required")
			return
		}
		var p principal
		err = s.db.QueryRow(r.Context(), `
			SELECT s.id,u.id,u.username,u.must_change_password,(s.mfa_verified_at IS NOT NULL)
			FROM sessions s
			JOIN users u ON u.id=s.user_id
			WHERE s.token_hash=$1 AND s.revoked_at IS NULL AND s.expires_at>now() AND u.active=true
		`, security.SHA256String(cookie.Value)).Scan(&p.SessionID, &p.UserID, &p.Username, &p.MustChangePassword, &p.MFAVerified)
		if err != nil {
			problem(w, 401, "authentication required")
			return
		}
		_, _ = s.db.Exec(r.Context(), "UPDATE sessions SET last_seen_at=now() WHERE id=$1", p.SessionID)
		next(w, r.WithContext(context.WithValue(r.Context(), principalKey, p)))
	}
}

func (s *Server) withPrincipal(next http.HandlerFunc) http.HandlerFunc {
	return s.withPrincipalRaw(func(w http.ResponseWriter, r *http.Request) {
		p := r.Context().Value(principalKey).(principal)
		required, err := s.mfa.Required(r.Context(), p.UserID, nil)
		if err != nil {
			problem(w, 500, "MFA policy lookup failed")
			return
		}
		if required && !p.MFAVerified {
			problem(w, 403, "MFA verification required")
			return
		}
		next(w, r)
	})
}

func (s *Server) require(permission string, next http.HandlerFunc) http.HandlerFunc {
	return s.withPrincipal(func(w http.ResponseWriter, r *http.Request) {
		p := r.Context().Value(principalKey).(principal)
		if p.MustChangePassword {
			problem(w, 403, "password change required")
			return
		}
		var ok bool
		e := s.db.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM role_assignments ra JOIN role_permissions rp ON rp.role_id=ra.role_id JOIN permissions p ON p.id=rp.permission_id WHERE ra.user_id=$1 AND p.name=$2)", p.UserID, permission).Scan(&ok)
		if e != nil || !ok {
			problem(w, 403, "permission denied")
			return
		}
		next(w, r)
	})
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	rows, e := s.db.Query(r.Context(), "SELECT id,username,email,display_name,active,must_change_password,locked_until,created_at FROM users ORDER BY username LIMIT 500")
	if e != nil {
		problem(w, 500, "database error")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, u, em, d string
		var active, mustChange bool
		var locked *time.Time
		var created time.Time
		if rows.Scan(&id, &u, &em, &d, &active, &mustChange, &locked, &created) != nil {
			problem(w, 500, "database error")
			return
		}
		items = append(items, map[string]any{"id": id, "username": u, "email": em, "display_name": d, "active": active, "must_change_password": mustChange, "locked_until": locked, "created_at": created})
	}
	writeJSON(w, 200, map[string]any{"items": items})
}
func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username    string `json:"username"`
		Email       string `json:"email"`
		DisplayName string `json:"display_name"`
		Password    string `json:"password"`
	}
	if decodeJSON(w, r, &in) != nil {
		return
	}
	policy, e := s.getSecurityPolicy(r)
	if e != nil {
		problem(w, 500, "database error")
		return
	}
	if violation := passwordPolicyViolation(policy, in.Password); violation != "" {
		problem(w, 400, violation)
		return
	}
	hash, e := security.HashPassword(in.Password)
	if e != nil {
		problem(w, 400, e.Error())
		return
	}
	tx, e := s.db.Begin(r.Context())
	if e != nil {
		problem(w, 500, "database error")
		return
	}
	defer tx.Rollback(r.Context())
	var id string
	if e = tx.QueryRow(r.Context(), "INSERT INTO users(username,email,display_name,must_change_password) VALUES(lower($1),lower($2),$3,true) RETURNING id", strings.TrimSpace(in.Username), strings.TrimSpace(in.Email), strings.TrimSpace(in.DisplayName)).Scan(&id); e != nil {
		problem(w, 409, "username or email already exists")
		return
	}
	if _, e = tx.Exec(r.Context(), "INSERT INTO password_credentials(user_id,password_hash) VALUES($1,$2)", id, hash); e != nil {
		problem(w, 500, "database error")
		return
	}
	if _, e = tx.Exec(r.Context(), "INSERT INTO role_assignments(user_id,role_id) SELECT $1,id FROM roles WHERE name='User' ON CONFLICT DO NOTHING", id); e != nil {
		problem(w, 500, "database error")
		return
	}
	p := r.Context().Value(principalKey).(principal)
	if e = s.auditTx(r.Context(), tx, &p.UserID, "USER_CREATED", "user", id, "success", r); e != nil {
		problem(w, 500, "audit error")
		return
	}
	if e = tx.Commit(r.Context()); e != nil {
		problem(w, 500, "database error")
		return
	}
	writeJSON(w, 201, map[string]string{"id": id})
}
func (s *Server) listGroups(w http.ResponseWriter, r *http.Request) {
	rows, e := s.db.Query(r.Context(), "SELECT id,name,description,created_at FROM groups ORDER BY name LIMIT 500")
	if e != nil {
		problem(w, 500, "database error")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, n, d string
		var created time.Time
		if rows.Scan(&id, &n, &d, &created) != nil {
			problem(w, 500, "database error")
			return
		}
		items = append(items, map[string]any{"id": id, "name": n, "description": d, "created_at": created})
	}
	writeJSON(w, 200, map[string]any{"items": items})
}
func (s *Server) createGroup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if decodeJSON(w, r, &in) != nil {
		return
	}
	var id string
	if e := s.db.QueryRow(r.Context(), "INSERT INTO groups(name,description) VALUES($1,$2) RETURNING id", strings.TrimSpace(in.Name), strings.TrimSpace(in.Description)).Scan(&id); e != nil {
		problem(w, 409, "group already exists")
		return
	}
	p := r.Context().Value(principalKey).(principal)
	_ = s.audit(r.Context(), &p.UserID, "GROUP_CREATED", "group", id, "success", r)
	writeJSON(w, 201, map[string]string{"id": id})
}
func (s *Server) addGroupMember(w http.ResponseWriter, r *http.Request) {
	var in struct {
		UserID string `json:"user_id"`
	}
	if decodeJSON(w, r, &in) != nil {
		return
	}
	gid := r.PathValue("id")
	var valid bool
	if e := s.db.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM groups g,users u WHERE g.id=$1::uuid AND u.id=$2::uuid)", gid, in.UserID).Scan(&valid); e != nil {
		problem(w, 400, "invalid group or user identifier")
		return
	}
	if !valid {
		problem(w, 404, "group or user not found")
		return
	}
	if _, e := s.db.Exec(r.Context(), "INSERT INTO group_memberships(group_id,user_id) VALUES($1::uuid,$2::uuid) ON CONFLICT DO NOTHING", gid, in.UserID); e != nil {
		problem(w, 500, "failed to add group membership")
		return
	}
	p := r.Context().Value(principalKey).(principal)
	_ = s.audit(r.Context(), &p.UserID, "GROUP_MEMBERSHIP_ADDED", "group", gid, "success", r)
	w.WriteHeader(204)
}
func (s *Server) listApplications(w http.ResponseWriter, r *http.Request) {
	rows, e := s.db.Query(r.Context(), `
		SELECT a.id,a.name,a.protocol,a.enabled,
		       COALESCE(c.client_id,''),
		       COALESCE(c.public_client,false),
		       COALESCE(c.require_pkce,false),
		       COALESCE(c.allowed_scopes,ARRAY[]::text[]),
		       COALESCE(c.initiate_login_uri,sp.initiate_login_uri,''),
		       COALESCE(sp.entity_id,''),
		       a.created_at
		FROM applications a
		LEFT JOIN oauth_clients c ON c.application_id=a.id
		LEFT JOIN saml_service_providers sp ON sp.application_id=a.id
		ORDER BY a.name
		LIMIT 500
	`)
	if e != nil {
		problem(w, 500, "database error")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, name, protocol, clientID, initiateLoginURI, entityID string
		var enabled, publicClient, requirePKCE bool
		var scopes []string
		var created time.Time
		if rows.Scan(
			&id, &name, &protocol, &enabled,
			&clientID, &publicClient, &requirePKCE, &scopes,
			&initiateLoginURI, &entityID, &created,
		) != nil {
			problem(w, 500, "database error")
			return
		}
		items = append(items, map[string]any{
			"id":                 id,
			"name":               name,
			"protocol":           protocol,
			"enabled":            enabled,
			"client_id":          clientID,
			"entity_id":          entityID,
			"public_client":      publicClient,
			"require_pkce":       requirePKCE,
			"allowed_scopes":     scopes,
			"initiate_login_uri": initiateLoginURI,
			"created_at":         created,
		})
	}
	writeJSON(w, 200, map[string]any{"items": items})
}
func (s *Server) createApplication(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name                   string   `json:"name"`
		PublicClient           bool     `json:"public_client"`
		RedirectURIs           []string `json:"redirect_uris"`
		PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris"`
		AllowedScopes          []string `json:"allowed_scopes"`
		InitiateLoginURI       string   `json:"initiate_login_uri"`
	}
	if decodeJSON(w, r, &in) != nil {
		return
	}
	if len(in.RedirectURIs) == 0 {
		problem(w, 400, "at least one redirect URI is required")
		return
	}
	for _, raw := range append(append([]string{}, in.RedirectURIs...), in.PostLogoutRedirectURIs...) {
		u, e := url.Parse(raw)
		if e != nil || u.Scheme == "" || u.Host == "" || u.Fragment != "" || strings.Contains(raw, "*") {
			problem(w, 400, "invalid redirect URI")
			return
		}
	}
	if in.InitiateLoginURI != "" {
		u, err := url.Parse(in.InitiateLoginURI)
		if err != nil || u.Scheme == "" || u.Host == "" || u.Fragment != "" || strings.Contains(in.InitiateLoginURI, "*") {
			problem(w, 400, "invalid initiate_login_uri")
			return
		}
	}
	if len(in.AllowedScopes) == 0 {
		in.AllowedScopes = []string{"openid", "profile", "email", "groups"}
	}
	normalized, scopes, e := normalizeRequestedScope(strings.Join(in.AllowedScopes, " "))
	if e != nil || !contains(scopes, "openid") {
		problem(w, 400, "OIDC applications must allow the openid scope")
		return
	}
	_ = normalized
	clientID, e := security.RandomToken(18)
	if e != nil {
		problem(w, 500, "entropy failure")
		return
	}
	secret, secretHash := "", ""
	if !in.PublicClient {
		secret, e = security.RandomToken(32)
		if e != nil {
			problem(w, 500, "entropy failure")
			return
		}
		secretHash = security.SHA256String(secret)
	}
	tx, e := s.db.Begin(r.Context())
	if e != nil {
		problem(w, 500, "database error")
		return
	}
	defer tx.Rollback(r.Context())
	var id string
	if e = tx.QueryRow(r.Context(), "INSERT INTO applications(name,protocol) VALUES($1,'oidc') RETURNING id", strings.TrimSpace(in.Name)).Scan(&id); e != nil {
		problem(w, 409, "application already exists")
		return
	}
	if _, e = tx.Exec(r.Context(), "INSERT INTO oauth_clients(application_id,client_id,client_secret_hash,public_client,require_pkce,allowed_scopes,initiate_login_uri) VALUES($1,$2,NULLIF($3,''),$4,true,$5,NULLIF($6,''))", id, clientID, secretHash, in.PublicClient, scopes, strings.TrimSpace(in.InitiateLoginURI)); e != nil {
		problem(w, 500, "database error")
		return
	}
	for _, uri := range in.RedirectURIs {
		if _, e = tx.Exec(r.Context(), "INSERT INTO oauth_redirect_uris(application_id,redirect_uri) VALUES($1,$2)", id, uri); e != nil {
			problem(w, 500, "database error")
			return
		}
	}
	for _, uri := range in.PostLogoutRedirectURIs {
		if _, e = tx.Exec(r.Context(), "INSERT INTO oauth_post_logout_redirect_uris(application_id,redirect_uri) VALUES($1,$2)", id, uri); e != nil {
			problem(w, 500, "database error")
			return
		}
	}
	p := r.Context().Value(principalKey).(principal)
	if e = s.auditTx(r.Context(), tx, &p.UserID, "APPLICATION_CREATED", "application", id, "success", r); e != nil {
		problem(w, 500, "audit error")
		return
	}
	if e = tx.Commit(r.Context()); e != nil {
		problem(w, 500, "database error")
		return
	}
	writeJSON(w, 201, map[string]any{"id": id, "client_id": clientID, "client_secret": secret, "allowed_scopes": scopes, "initiate_login_uri": strings.TrimSpace(in.InitiateLoginURI)})
}
func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	query := "SELECT id,occurred_at,COALESCE(actor_user_id::text,''),target_type,target_id,event,result,COALESCE(ip::text,''),request_id FROM audit_events WHERE 1=1"
	args := []any{}
	add := func(condition string, value string) {
		if value == "" {
			return
		}
		args = append(args, value)
		query += fmt.Sprintf(" AND "+condition, len(args))
	}
	q := r.URL.Query()
	if userID := q.Get("user_id"); userID != "" {
		args = append(args, userID)
		n := len(args)
		query += fmt.Sprintf(" AND (COALESCE(actor_user_id::text,'')=$%d OR (target_type='user' AND target_id=$%d))", n, n)
	}
	add("(target_type='application' AND target_id=$%d)", q.Get("application_id"))
	add("event=$%d", q.Get("event"))
	add("COALESCE(ip::text,'')=$%d", q.Get("ip"))
	add("result=$%d", q.Get("result"))
	query += " ORDER BY occurred_at DESC LIMIT 500"

	rows, e := s.db.Query(r.Context(), query, args...)
	if e != nil {
		problem(w, 500, "database error")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id int64
		var t time.Time
		var actor, tt, tid, event, result, ip, rid string
		if rows.Scan(&id, &t, &actor, &tt, &tid, &event, &result, &ip, &rid) != nil {
			problem(w, 500, "database error")
			return
		}
		items = append(items, map[string]any{"id": id, "occurred_at": t, "actor_user_id": actor, "target_type": tt, "target_id": tid, "event": event, "result": result, "ip": ip, "request_id": rid})
	}
	writeJSON(w, 200, map[string]any{"items": items})
}
func (s *Server) audit(ctx context.Context, actor *string, event, targetType, targetID, result string, r *http.Request) error {
	_, e := s.db.Exec(ctx, "INSERT INTO audit_events(actor_user_id,target_type,target_id,event,result,ip,user_agent,request_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8)", actor, targetType, targetID, event, result, nullableIP(clientIP(r)), truncate(r.UserAgent(), 512), fmt.Sprint(ctx.Value(requestIDKey)))
	return e
}
func (s *Server) auditTx(ctx context.Context, tx pgx.Tx, actor *string, event, targetType, targetID, result string, r *http.Request) error {
	_, e := tx.Exec(ctx, "INSERT INTO audit_events(actor_user_id,target_type,target_id,event,result,ip,user_agent,request_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8)", actor, targetType, targetID, event, result, nullableIP(clientIP(r)), truncate(r.UserAgent(), 512), fmt.Sprint(ctx.Value(requestIDKey)))
	return e
}
func (s *Server) allowLogin(ctx context.Context, ip string) bool {
	key := "opensso:login:" + ip
	n, e := s.redis.Incr(ctx, key).Result()
	if e != nil {
		return false
	}
	if n == 1 {
		_ = s.redis.Expire(ctx, key, 5*time.Minute).Err()
	}
	return n <= 30
}
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(dst); e != nil {
		problem(w, 400, "invalid JSON body")
		return e
	}
	return nil
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func problem(w http.ResponseWriter, status int, detail string) {
	writeJSON(w, status, map[string]any{"error": http.StatusText(status), "detail": detail})
}
func clientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		candidate := strings.TrimSpace(strings.Split(forwarded, ",")[0])
		if net.ParseIP(candidate) != nil {
			return candidate
		}
	}
	if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); net.ParseIP(realIP) != nil {
		return realIP
	}
	h, _, e := net.SplitHostPort(r.RemoteAddr)
	if e == nil {
		return h
	}
	return r.RemoteAddr
}
func nullableIP(ip string) any {
	if net.ParseIP(ip) == nil {
		return nil
	}
	return ip
}
func truncate(v string, n int) string {
	if len(v) > n {
		return v[:n]
	}
	return v
}

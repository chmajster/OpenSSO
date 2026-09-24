package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	mfadomain "github.com/chmajster/OpenSSO/backend/internal/mfa"
)

func (s *Server) myMFAStatus(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(principalKey).(principal)
	status, err := s.mfa.Status(r.Context(), p.UserID, nil)
	if err != nil {
		problem(w, 500, "MFA status lookup failed")
		return
	}
	credentials, err := s.mfa.ListWebAuthn(r.Context(), p.UserID)
	if err != nil {
		problem(w, 500, "WebAuthn credential lookup failed")
		return
	}
	writeJSON(w, 200, map[string]any{
		"required":                 status.Required,
		"session_verified":         p.MFAVerified,
		"totp_enabled":             status.TOTPEnabled,
		"webauthn_credentials":     credentials,
		"passkeys":                 status.Passkeys,
		"recovery_codes_remaining": status.RecoveryCodesRemaining,
		"has_primary_factor":       status.HasPrimaryFactor,
	})
}

func (s *Server) beginTOTPEnrollment(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(principalKey).(principal)
	if !s.allowMFAMutation(w, r, p) {
		return
	}
	if !s.mfa.Allow(r.Context(), "totp-enroll", p.UserID+":"+clientIP(r), 10, 5*time.Minute) {
		problem(w, 429, "too many MFA enrollment attempts")
		return
	}
	enrollment, err := s.mfa.BeginTOTP(r.Context(), p.UserID, p.Username)
	if err != nil {
		s.handleMFAError(w, err)
		return
	}
	_ = s.audit(r.Context(), &p.UserID, "MFA_ENROLLMENT_STARTED", "user", p.UserID, "success", r)
	writeJSON(w, 200, enrollment)
}

func (s *Server) confirmTOTPEnrollment(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(principalKey).(principal)
	if !s.allowMFAMutation(w, r, p) {
		return
	}
	if !s.mfa.Allow(r.Context(), "totp-confirm", p.UserID+":"+clientIP(r), 10, 5*time.Minute) {
		problem(w, 429, "too many MFA enrollment attempts")
		return
	}
	var in struct {
		Code string `json:"code"`
	}
	if decodeJSON(w, r, &in) != nil {
		return
	}
	recoveryCodes, err := s.mfa.ConfirmTOTP(r.Context(), p.UserID, in.Code)
	if err != nil {
		_ = s.audit(r.Context(), &p.UserID, "MFA_CHALLENGE_FAILED", "user", p.UserID, "failure", r)
		s.handleMFAError(w, err)
		return
	}
	if err = s.markSessionMFAVerified(r, p); err != nil {
		problem(w, 500, "failed to update MFA session assurance")
		return
	}
	_ = s.audit(r.Context(), &p.UserID, "MFA_ADDED", "user", p.UserID, "success", r)
	writeJSON(w, 200, map[string]any{"verified": true, "recovery_codes": recoveryCodes})
}

func (s *Server) disableTOTP(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(principalKey).(principal)
	if !s.allowMFAMutation(w, r, p) {
		return
	}
	if err := s.mfa.DisableTOTP(r.Context(), p.UserID); err != nil {
		s.handleMFAError(w, err)
		return
	}
	_ = s.audit(r.Context(), &p.UserID, "MFA_REMOVED", "user", p.UserID, "success", r)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) regenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(principalKey).(principal)
	status, err := s.mfa.Status(r.Context(), p.UserID, nil)
	if err != nil {
		problem(w, 500, "MFA status lookup failed")
		return
	}
	if !status.HasPrimaryFactor {
		problem(w, 409, "enroll TOTP, a security key, or a passkey before generating recovery codes")
		return
	}
	if !p.MFAVerified {
		problem(w, 403, "MFA verification required before regenerating recovery codes")
		return
	}
	if !s.mfa.Allow(r.Context(), "recovery-regenerate", p.UserID+":"+clientIP(r), 5, 10*time.Minute) {
		problem(w, 429, "too many recovery-code operations")
		return
	}
	codes, err := s.mfa.RegenerateRecoveryCodes(r.Context(), p.UserID)
	if err != nil {
		problem(w, 500, "failed to regenerate recovery codes")
		return
	}
	_ = s.audit(r.Context(), &p.UserID, "MFA_RECOVERY_REGENERATED", "user", p.UserID, "success", r)
	writeJSON(w, 200, map[string]any{"recovery_codes": codes})
}

func (s *Server) beginWebAuthnRegistration(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(principalKey).(principal)
	if !s.allowMFAMutation(w, r, p) {
		return
	}
	if !s.mfa.Allow(r.Context(), "webauthn-register", p.UserID+":"+clientIP(r), 10, 5*time.Minute) {
		problem(w, 429, "too many WebAuthn enrollment attempts")
		return
	}
	var in struct {
		Kind string `json:"kind"`
	}
	if decodeJSON(w, r, &in) != nil {
		return
	}
	begin, err := s.mfa.BeginWebAuthnRegistration(r.Context(), p.UserID, strings.TrimSpace(in.Kind))
	if err != nil {
		s.handleMFAError(w, err)
		return
	}
	_ = s.audit(r.Context(), &p.UserID, "MFA_ENROLLMENT_STARTED", "user", p.UserID, "success", r)
	writeJSON(w, 200, begin)
}

func (s *Server) finishWebAuthnRegistration(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(principalKey).(principal)
	if !s.allowMFAMutation(w, r, p) {
		return
	}
	if !s.mfa.Allow(r.Context(), "webauthn-register-finish", p.UserID+":"+clientIP(r), 10, 5*time.Minute) {
		problem(w, 429, "too many WebAuthn enrollment attempts")
		return
	}
	ceremony := r.URL.Query().Get("ceremony")
	displayName := r.URL.Query().Get("display_name")
	credential, err := s.mfa.FinishWebAuthnRegistration(r.Context(), p.UserID, ceremony, displayName, r)
	if err != nil {
		_ = s.audit(r.Context(), &p.UserID, "MFA_CHALLENGE_FAILED", "user", p.UserID, "failure", r)
		s.handleMFAError(w, err)
		return
	}
	recoveryCodes, err := s.mfa.EnsureRecoveryCodes(r.Context(), p.UserID)
	if err != nil {
		problem(w, 500, "failed to ensure recovery codes")
		return
	}
	if err = s.markSessionMFAVerified(r, p); err != nil {
		problem(w, 500, "failed to update MFA session assurance")
		return
	}
	_ = s.audit(r.Context(), &p.UserID, "MFA_ADDED", "user", p.UserID, "success", r)
	writeJSON(w, 201, map[string]any{"credential": credential, "recovery_codes": recoveryCodes})
}

func (s *Server) deleteWebAuthnCredential(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(principalKey).(principal)
	if !s.allowMFAMutation(w, r, p) {
		return
	}
	if err := s.mfa.DeleteWebAuthn(r.Context(), p.UserID, r.PathValue("id")); err != nil {
		s.handleMFAError(w, err)
		return
	}
	_ = s.audit(r.Context(), &p.UserID, "MFA_REMOVED", "user", p.UserID, "success", r)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) verifyMFAFactor(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(principalKey).(principal)
	if !s.mfa.Allow(r.Context(), "verify", p.UserID+":"+clientIP(r), 10, 5*time.Minute) {
		problem(w, 429, "too many MFA verification attempts")
		return
	}
	var in struct {
		Method string `json:"method"`
		Code   string `json:"code"`
	}
	if decodeJSON(w, r, &in) != nil {
		return
	}
	method := strings.TrimSpace(in.Method)
	if err := s.mfa.VerifyFactor(r.Context(), p.UserID, method, in.Code); err != nil {
		_ = s.audit(r.Context(), &p.UserID, "MFA_CHALLENGE_FAILED", "user", p.UserID, "failure", r)
		s.handleMFAError(w, err)
		return
	}
	if err := s.markSessionMFAVerified(r, p); err != nil {
		problem(w, 500, "failed to update MFA session assurance")
		return
	}
	event := "MFA_CHALLENGE_SUCCESS"
	if method == "recovery" {
		event = "MFA_RECOVERY_USED"
	}
	_ = s.audit(r.Context(), &p.UserID, event, "user", p.UserID, "success", r)
	_ = s.audit(r.Context(), &p.UserID, "LOGIN_SUCCESS", "user", p.UserID, "success", r)
	writeJSON(w, 200, map[string]bool{"verified": true})
}

func (s *Server) beginWebAuthnAuthentication(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(principalKey).(principal)
	if !s.mfa.Allow(r.Context(), "webauthn-verify", p.UserID+":"+clientIP(r), 10, 5*time.Minute) {
		problem(w, 429, "too many MFA verification attempts")
		return
	}
	begin, err := s.mfa.BeginWebAuthnLogin(r.Context(), p.UserID)
	if err != nil {
		s.handleMFAError(w, err)
		return
	}
	writeJSON(w, 200, begin)
}

func (s *Server) finishWebAuthnAuthentication(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(principalKey).(principal)
	if !s.mfa.Allow(r.Context(), "webauthn-verify-finish", p.UserID+":"+clientIP(r), 10, 5*time.Minute) {
		problem(w, 429, "too many MFA verification attempts")
		return
	}
	credential, err := s.mfa.FinishWebAuthnLogin(r.Context(), p.UserID, r.URL.Query().Get("ceremony"), r)
	if err != nil {
		_ = s.audit(r.Context(), &p.UserID, "MFA_CHALLENGE_FAILED", "user", p.UserID, "failure", r)
		s.handleMFAError(w, err)
		return
	}
	if err = s.markSessionMFAVerified(r, p); err != nil {
		problem(w, 500, "failed to update MFA session assurance")
		return
	}
	_ = s.audit(r.Context(), &p.UserID, "MFA_CHALLENGE_SUCCESS", "webauthn_credential", credential.ID, "success", r)
	_ = s.audit(r.Context(), &p.UserID, "LOGIN_SUCCESS", "user", p.UserID, "success", r)
	writeJSON(w, 200, map[string]any{"verified": true, "credential": credential})
}

func (s *Server) adminUserMFAStatus(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	status, err := s.mfa.Status(r.Context(), userID, nil)
	if err != nil {
		problem(w, 500, "MFA status lookup failed")
		return
	}
	credentials, err := s.mfa.ListWebAuthn(r.Context(), userID)
	if err != nil {
		problem(w, 500, "WebAuthn credential lookup failed")
		return
	}
	writeJSON(w, 200, map[string]any{"status": status, "webauthn_credentials": credentials})
}

func (s *Server) resetUserMFA(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	if err := s.mfa.ResetUser(r.Context(), userID); err != nil {
		problem(w, 500, "failed to reset MFA")
		return
	}
	p := r.Context().Value(principalKey).(principal)
	_ = s.audit(r.Context(), &p.UserID, "MFA_RESET", "user", userID, "success", r)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) groupMFAPolicy(w http.ResponseWriter, r *http.Request) {
	required, err := s.mfa.GroupPolicy(r.Context(), r.PathValue("id"))
	if err != nil {
		problem(w, 500, "MFA policy lookup failed")
		return
	}
	writeJSON(w, 200, map[string]bool{"required": required})
}

func (s *Server) updateGroupMFAPolicy(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Required bool `json:"required"`
	}
	if decodeJSON(w, r, &in) != nil {
		return
	}
	id := r.PathValue("id")
	if err := s.mfa.SetGroupPolicy(r.Context(), id, in.Required); err != nil {
		problem(w, 400, "failed to update group MFA policy")
		return
	}
	p := r.Context().Value(principalKey).(principal)
	_ = s.audit(r.Context(), &p.UserID, "MFA_POLICY_CHANGED", "group", id, "success", r)
	writeJSON(w, 200, in)
}

func (s *Server) applicationMFAPolicy(w http.ResponseWriter, r *http.Request) {
	required, err := s.mfa.ApplicationPolicy(r.Context(), r.PathValue("id"))
	if err != nil {
		problem(w, 500, "MFA policy lookup failed")
		return
	}
	writeJSON(w, 200, map[string]bool{"required": required})
}

func (s *Server) updateApplicationMFAPolicy(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Required bool `json:"required"`
	}
	if decodeJSON(w, r, &in) != nil {
		return
	}
	id := r.PathValue("id")
	if err := s.mfa.SetApplicationPolicy(r.Context(), id, in.Required); err != nil {
		problem(w, 400, "failed to update application MFA policy")
		return
	}
	p := r.Context().Value(principalKey).(principal)
	_ = s.audit(r.Context(), &p.UserID, "MFA_POLICY_CHANGED", "application", id, "success", r)
	writeJSON(w, 200, in)
}

func (s *Server) allowMFAMutation(w http.ResponseWriter, r *http.Request, p principal) bool {
	status, err := s.mfa.Status(r.Context(), p.UserID, nil)
	if err != nil {
		problem(w, 500, "MFA status lookup failed")
		return false
	}
	if status.HasPrimaryFactor && !p.MFAVerified {
		problem(w, 403, "MFA verification required before changing MFA factors")
		return false
	}
	return true
}

func (s *Server) markSessionMFAVerified(r *http.Request, p principal) error {
	tag, err := s.db.Exec(r.Context(), `
		UPDATE sessions SET mfa_verified_at=now(),last_seen_at=now()
		WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>now()
	`, p.SessionID, p.UserID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("active session not found")
	}
	return nil
}

func (s *Server) handleMFAError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, mfadomain.ErrInvalidCode):
		problem(w, 401, "invalid MFA verification")
	case errors.Is(err, mfadomain.ErrNotEnrolled):
		problem(w, 404, err.Error())
	case errors.Is(err, mfadomain.ErrAlreadyEnrolled):
		problem(w, 409, err.Error())
	case errors.Is(err, mfadomain.ErrLastRequiredFactor):
		problem(w, 409, err.Error())
	default:
		problem(w, 400, err.Error())
	}
}

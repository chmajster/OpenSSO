package httpapi

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/chmajster/OpenSSO/backend/internal/samlidp"
)

func validateSAMLInitiateLoginURI(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Fragment != "" {
		return errors.New("invalid initiate_login_uri")
	}
	return nil
}

func (s *Server) createSAMLApplication(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name                      string `json:"name"`
		InitiateLoginURI          string `json:"initiate_login_uri"`
		MetadataXML               string `json:"metadata_xml"`
		RequireSignedAuthnRequest bool   `json:"require_signed_authn_request"`
	}
	if decodeJSON(w, r, &in) != nil {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	in.InitiateLoginURI = strings.TrimSpace(in.InitiateLoginURI)
	if in.Name == "" {
		problem(w, 400, "application name is required")
		return
	}
	if err := validateSAMLInitiateLoginURI(in.InitiateLoginURI); err != nil {
		problem(w, 400, err.Error())
		return
	}
	entityID, err := samlidp.ValidateServiceProviderMetadata(in.MetadataXML)
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

	var id string
	if err = tx.QueryRow(r.Context(), `
		INSERT INTO applications(name,protocol)
		VALUES($1,'saml')
		RETURNING id
	`, in.Name).Scan(&id); err != nil {
		problem(w, 409, "application name already exists")
		return
	}
	if _, err = tx.Exec(r.Context(), `
		INSERT INTO saml_service_providers(
			application_id,entity_id,metadata_xml,require_signed_authn_requests,initiate_login_uri
		) VALUES($1,$2,$3,$4,NULLIF($5,''))
	`, id, entityID, in.MetadataXML, in.RequireSignedAuthnRequest, in.InitiateLoginURI); err != nil {
		problem(w, 409, "SAML entityID already exists or metadata cannot be stored")
		return
	}

	p := r.Context().Value(principalKey).(principal)
	if err = s.auditTx(r.Context(), tx, &p.UserID, "SAML_APPLICATION_CREATED", "application", id, "success", r); err != nil {
		problem(w, 500, "audit error")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		problem(w, 500, "database error")
		return
	}
	writeJSON(w, 201, map[string]any{
		"id": id, "protocol": "saml", "entity_id": entityID,
		"require_signed_authn_request": in.RequireSignedAuthnRequest,
		"initiate_login_uri": in.InitiateLoginURI,
	})
}

func (s *Server) updateSAMLApplication(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in struct {
		Name                      string `json:"name"`
		Enabled                   bool   `json:"enabled"`
		InitiateLoginURI          string `json:"initiate_login_uri"`
		MetadataXML               string `json:"metadata_xml"`
		RequireSignedAuthnRequest bool   `json:"require_signed_authn_request"`
	}
	if decodeJSON(w, r, &in) != nil {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	in.InitiateLoginURI = strings.TrimSpace(in.InitiateLoginURI)
	if in.Name == "" {
		problem(w, 400, "application name is required")
		return
	}
	if err := validateSAMLInitiateLoginURI(in.InitiateLoginURI); err != nil {
		problem(w, 400, err.Error())
		return
	}
	entityID, err := samlidp.ValidateServiceProviderMetadata(in.MetadataXML)
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

	tag, err := tx.Exec(r.Context(), `
		UPDATE applications SET name=$1,enabled=$2
		WHERE id=$3 AND protocol='saml'
	`, in.Name, in.Enabled, id)
	if err != nil {
		problem(w, 409, "application name already exists or update failed")
		return
	}
	if tag.RowsAffected() != 1 {
		problem(w, 404, "SAML application not found")
		return
	}
	if _, err = tx.Exec(r.Context(), `
		UPDATE saml_service_providers
		SET entity_id=$1,metadata_xml=$2,require_signed_authn_requests=$3,
		    initiate_login_uri=NULLIF($4,''),updated_at=now()
		WHERE application_id=$5
	`, entityID, in.MetadataXML, in.RequireSignedAuthnRequest, in.InitiateLoginURI, id); err != nil {
		problem(w, 409, "SAML entityID already exists or update failed")
		return
	}

	p := r.Context().Value(principalKey).(principal)
	if err = s.auditTx(r.Context(), tx, &p.UserID, "SAML_APPLICATION_UPDATED", "application", id, "success", r); err != nil {
		problem(w, 500, "audit error")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		problem(w, 500, "database error")
		return
	}
	writeJSON(w, 200, map[string]any{
		"id": id, "protocol": "saml", "entity_id": entityID, "enabled": in.Enabled,
		"require_signed_authn_request": in.RequireSignedAuthnRequest,
		"initiate_login_uri": in.InitiateLoginURI,
	})
}

func (s *Server) samlApplicationIntegration(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var name, entityID, metadataXML string
	var enabled, requireSigned bool
	var initiateLoginURI *string
	err := s.db.QueryRow(r.Context(), `
		SELECT a.name,a.enabled,sp.entity_id,sp.metadata_xml,
		       sp.require_signed_authn_requests,sp.initiate_login_uri
		FROM applications a
		JOIN saml_service_providers sp ON sp.application_id=a.id
		WHERE a.id=$1 AND a.protocol='saml'
	`, id).Scan(&name, &enabled, &entityID, &metadataXML, &requireSigned, &initiateLoginURI)
	if err != nil {
		problem(w, 404, "SAML application not found")
		return
	}
	writeJSON(w, 200, map[string]any{
		"id":                           id,
		"name":                         name,
		"protocol":                     "saml",
		"enabled":                      enabled,
		"sp_entity_id":                 entityID,
		"sp_metadata_xml":              metadataXML,
		"require_signed_authn_request": requireSigned,
		"initiate_login_uri":           initiateLoginURI,
		"idp_entity_id":                s.saml.EntityID(),
		"idp_metadata_url":             strings.TrimRight(s.cfg.PublicURL, "/") + "/saml/metadata",
		"sso_url":                      strings.TrimRight(s.cfg.PublicURL, "/") + "/saml/sso",
		"certificate_url":              strings.TrimRight(s.cfg.PublicURL, "/") + "/saml/certificate",
		"name_id_format":               "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		"request_binding":               "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
		"response_binding":              "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
	})
}

func (s *Server) samlCertificates(w http.ResponseWriter, r *http.Request) {
	items, err := s.saml.CertificateMetadata(r.Context())
	if err != nil {
		problem(w, 500, "failed to read SAML certificate metadata")
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) rotateSAMLCertificate(w http.ResponseWriter, r *http.Request) {
	if err := s.saml.RotateCertificate(r.Context()); err != nil {
		problem(w, 500, "SAML signing certificate rotation failed")
		return
	}
	p := r.Context().Value(principalKey).(principal)
	_ = s.audit(r.Context(), &p.UserID, "SAML_CERTIFICATE_ROTATED", "saml_certificate", "", "success", r)
	items, err := s.saml.CertificateMetadata(r.Context())
	if err != nil {
		problem(w, 500, "SAML certificate rotated but metadata lookup failed")
		return
	}
	writeJSON(w, 201, map[string]any{"items": items})
}

func (s *Server) continueSAML(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(principalKey).(principal)
	if p.MustChangePassword {
		problem(w, 403, "password change required")
		return
	}
	var in struct {
		RequestID string `json:"request_id"`
	}
	if decodeJSON(w, r, &in) != nil {
		return
	}
	in.RequestID = strings.TrimSpace(in.RequestID)
	if in.RequestID == "" || len(in.RequestID) > 256 {
		problem(w, 400, "invalid SAML request ID")
		return
	}
	applicationID, err := s.saml.FinalizeAuthRequest(r.Context(), in.RequestID, p.UserID)
	switch {
	case errors.Is(err, samlidp.ErrAuthRequestNotFound):
		problem(w, 404, "SAML authentication request not found or expired")
		return
	case errors.Is(err, samlidp.ErrAccessDenied):
		_ = s.audit(r.Context(), &p.UserID, "SAML_LOGIN_DENIED", "application", applicationID, "failure", r)
		problem(w, 403, "user is not assigned to this SAML application")
		return
	case err != nil:
		problem(w, 500, "failed to finalize SAML authentication request")
		return
	}
	_ = s.audit(r.Context(), &p.UserID, "SAML_LOGIN_CONTINUED", "application", applicationID, "success", r)
	writeJSON(w, 200, map[string]string{"callback_url": s.saml.CallbackURL(in.RequestID)})
}

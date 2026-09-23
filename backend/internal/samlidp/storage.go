package samlidp

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/chmajster/OpenSSO/backend/internal/security"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zitadel/saml/pkg/provider/key"
	"github.com/zitadel/saml/pkg/provider/models"
	"github.com/zitadel/saml/pkg/provider/serviceprovider"
	"github.com/zitadel/saml/pkg/provider/xml/samlp"
)

var (
	ErrAuthRequestNotFound = errors.New("SAML authentication request not found or expired")
	ErrAccessDenied        = errors.New("user is not assigned to SAML application")
)

type Storage struct {
	db           *pgxpool.Pool
	certificates *CertificateManager
	loginBaseURL string
}

func NewStorage(db *pgxpool.Pool, certificates *CertificateManager, loginBaseURL string) *Storage {
	return &Storage{db: db, certificates: certificates, loginBaseURL: loginBaseURL}
}

type AuthRequest struct {
	ID            string
	ApplicationID string
	RelayState    string
	ACSURL        string
	BindingType   string
	SAMLRequestID string
	Issuer        string
	Destination   string
	UserID        string
	Completed     bool
}

func (r *AuthRequest) GetID() string                       { return r.ID }
func (r *AuthRequest) GetApplicationID() string            { return r.ApplicationID }
func (r *AuthRequest) GetRelayState() string               { return r.RelayState }
func (r *AuthRequest) GetAccessConsumerServiceURL() string { return r.ACSURL }
func (r *AuthRequest) GetBindingType() string              { return r.BindingType }
func (r *AuthRequest) GetAuthRequestID() string            { return r.SAMLRequestID }
func (r *AuthRequest) GetIssuer() string                   { return r.Issuer }
func (r *AuthRequest) GetDestination() string              { return r.Destination }
func (r *AuthRequest) GetUserID() string                   { return r.UserID }
func (r *AuthRequest) Done() bool                          { return r.Completed && r.UserID != "" }

func (s *Storage) Health(ctx context.Context) error {
	return s.db.Ping(ctx)
}

func (s *Storage) GetCA(ctx context.Context) (*key.CertificateAndKey, error) {
	return s.certificates.Active(ctx)
}

func (s *Storage) GetMetadataSigningKey(ctx context.Context) (*key.CertificateAndKey, error) {
	return s.certificates.Active(ctx)
}

func (s *Storage) GetResponseSigningKey(ctx context.Context) (*key.CertificateAndKey, error) {
	return s.certificates.Active(ctx)
}

func (s *Storage) GetEntityByID(ctx context.Context, entityID string) (*serviceprovider.ServiceProvider, error) {
	var applicationID, metadataXML string
	var requireSigned bool
	err := s.db.QueryRow(ctx, `
		SELECT a.id,sp.metadata_xml,sp.require_signed_authn_requests
		FROM saml_service_providers sp
		JOIN applications a ON a.id=sp.application_id
		WHERE sp.entity_id=$1 AND a.enabled=true AND a.protocol='saml'
	`, entityID).Scan(&applicationID, &metadataXML, &requireSigned)
	if err != nil {
		return nil, err
	}
	sp, err := serviceprovider.NewServiceProvider(
		applicationID,
		&serviceprovider.Config{Metadata: []byte(metadataXML)},
		func(requestID string) string {
			target, _ := url.Parse(s.loginBaseURL)
			q := target.Query()
			q.Set("saml_request_id", requestID)
			target.RawQuery = q.Encode()
			return target.String()
		},
	)
	if err != nil {
		return nil, err
	}
	if requireSigned && sp.Metadata != nil && sp.Metadata.SPSSODescriptor != nil {
		sp.Metadata.SPSSODescriptor.AuthnRequestsSigned = "true"
	}
	return sp, nil
}

func (s *Storage) GetEntityIDByAppID(ctx context.Context, applicationID string) (string, error) {
	var entityID string
	err := s.db.QueryRow(ctx, `
		SELECT entity_id FROM saml_service_providers WHERE application_id=$1
	`, applicationID).Scan(&entityID)
	return entityID, err
}

func (s *Storage) CreateAuthRequest(
	ctx context.Context,
	request *samlp.AuthnRequestType,
	acsURL string,
	binding string,
	relayState string,
	applicationID string,
) (models.AuthRequestInt, error) {
	if request == nil || request.Id == "" || request.Issuer.Text == "" {
		return nil, errors.New("invalid SAML AuthnRequest")
	}
	if len(relayState) > 1024 {
		return nil, errors.New("SAML RelayState exceeds 1024 bytes")
	}
	if acsURL == "" || binding == "" {
		return nil, errors.New("SAML ACS URL and binding are required")
	}
	requestKey, err := security.RandomToken(32)
	if err != nil {
		return nil, err
	}
	_, err = s.db.Exec(ctx, `
		INSERT INTO saml_authn_requests(
			request_key,saml_request_id,application_id,issuer,destination,
			acs_url,response_binding,relay_state,expires_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,now()+interval '5 minutes')
	`, requestKey, request.Id, applicationID, request.Issuer.Text, request.Destination,
		acsURL, binding, relayState)
	if err != nil {
		return nil, fmt.Errorf("persist SAML AuthnRequest: %w", err)
	}
	return &AuthRequest{
		ID: requestKey, ApplicationID: applicationID, RelayState: relayState,
		ACSURL: acsURL, BindingType: binding, SAMLRequestID: request.Id,
		Issuer: request.Issuer.Text, Destination: request.Destination,
	}, nil
}

func (s *Storage) AuthRequestByID(ctx context.Context, requestKey string) (models.AuthRequestInt, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var r AuthRequest
	var userID *string
	var completedAt *time.Time
	err = tx.QueryRow(ctx, `
		SELECT request_key,application_id,relay_state,acs_url,response_binding,
		       saml_request_id,issuer,destination,user_id::text,completed_at
		FROM saml_authn_requests
		WHERE request_key=$1 AND expires_at>now() AND consumed_at IS NULL
		FOR UPDATE
	`, requestKey).Scan(
		&r.ID, &r.ApplicationID, &r.RelayState, &r.ACSURL, &r.BindingType,
		&r.SAMLRequestID, &r.Issuer, &r.Destination, &userID, &completedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAuthRequestNotFound
	}
	if err != nil {
		return nil, err
	}
	if userID == nil || completedAt == nil {
		return nil, errors.New("SAML authentication request is not completed")
	}
	r.UserID = *userID
	r.Completed = true

	tag, err := tx.Exec(ctx, `
		UPDATE saml_authn_requests
		SET consumed_at=now()
		WHERE request_key=$1 AND consumed_at IS NULL
	`, requestKey)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() != 1 {
		return nil, ErrAuthRequestNotFound
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Storage) FinalizeAuthRequest(ctx context.Context, requestKey, userID string) (string, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)

	var applicationID string
	err = tx.QueryRow(ctx, `
		SELECT application_id
		FROM saml_authn_requests
		WHERE request_key=$1 AND expires_at>now()
		  AND consumed_at IS NULL AND completed_at IS NULL
		FOR UPDATE
	`, requestKey).Scan(&applicationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrAuthRequestNotFound
	}
	if err != nil {
		return "", err
	}

	var allowed bool
	err = tx.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1
			FROM applications a
			WHERE a.id=$1 AND a.enabled=true AND a.protocol='saml'
			  AND (
				EXISTS(
					SELECT 1 FROM application_user_assignments ua
					WHERE ua.application_id=a.id AND ua.user_id=$2
				)
				OR EXISTS(
					SELECT 1
					FROM application_group_assignments ga
					JOIN group_memberships gm ON gm.group_id=ga.group_id
					WHERE ga.application_id=a.id AND gm.user_id=$2
				)
			  )
		)
	`, applicationID, userID).Scan(&allowed)
	if err != nil {
		return "", err
	}
	if !allowed {
		return "", ErrAccessDenied
	}

	tag, err := tx.Exec(ctx, `
		UPDATE saml_authn_requests
		SET user_id=$2,completed_at=now()
		WHERE request_key=$1 AND completed_at IS NULL AND consumed_at IS NULL
	`, requestKey, userID)
	if err != nil {
		return "", err
	}
	if tag.RowsAffected() != 1 {
		return "", ErrAuthRequestNotFound
	}
	if err = tx.Commit(ctx); err != nil {
		return "", err
	}
	return applicationID, nil
}

func (s *Storage) SetUserinfoWithUserID(
	ctx context.Context,
	applicationID string,
	userinfo models.AttributeSetter,
	userID string,
	_ []int,
) error {
	var username, email, displayName string
	var active bool
	err := s.db.QueryRow(ctx, `
		SELECT username,email,display_name,active FROM users WHERE id=$1
	`, userID).Scan(&username, &email, &displayName, &active)
	if err != nil {
		return err
	}
	if !active {
		return errors.New("SAML subject user is disabled")
	}
	groups, err := s.userGroups(ctx, userID)
	if err != nil {
		return err
	}

	// zitadel/saml currently emits an emailAddress NameID from SetUsername.
	// Use the verified account email as the NameID text and expose the local
	// username separately as an attribute.
	userinfo.SetUsername(email)
	userinfo.SetEmail(email)
	userinfo.SetFullName(displayName)
	userinfo.SetUserID(userID)
	userinfo.SetCustomAttribute(
		"username",
		"Username",
		"urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
		[]string{username},
	)
	if len(groups) > 0 {
		userinfo.SetCustomAttribute(
			"groups",
			"Groups",
			"urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			groups,
		)
	}
	return nil
}

func (s *Storage) SetUserinfoWithLoginName(
	ctx context.Context,
	userinfo models.AttributeSetter,
	loginName string,
	attributes []int,
) error {
	var userID string
	err := s.db.QueryRow(ctx, `
		SELECT id FROM users
		WHERE lower(username)=lower($1) OR lower(email)=lower($1)
	`, strings.TrimSpace(loginName)).Scan(&userID)
	if err != nil {
		return err
	}
	return s.SetUserinfoWithUserID(ctx, "", userinfo, userID, attributes)
}

func (s *Storage) userGroups(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.db.Query(ctx, `
		SELECT g.name
		FROM group_memberships gm
		JOIN groups g ON g.id=gm.group_id
		WHERE gm.user_id=$1
		ORDER BY g.name
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	groups := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		groups = append(groups, name)
	}
	return groups, rows.Err()
}

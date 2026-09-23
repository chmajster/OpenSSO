package mfa

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/chmajster/OpenSSO/backend/internal/security"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

type WebAuthnCredentialInfo struct {
	ID           string     `json:"id"`
	DisplayName  string     `json:"display_name"`
	Discoverable bool       `json:"discoverable"`
	CreatedAt    time.Time  `json:"created_at"`
	LastUsedAt   *time.Time `json:"last_used_at"`
}

type WebAuthnBegin struct {
	Ceremony string `json:"ceremony"`
	Options  any    `json:"options"`
}

type webAuthnProvider interface {
	BeginRegistration(context.Context, string, string) (WebAuthnBegin, error)
	FinishRegistration(context.Context, string, string, string, *http.Request) (WebAuthnCredentialInfo, error)
	BeginLogin(context.Context, string) (WebAuthnBegin, error)
	FinishLogin(context.Context, string, string, *http.Request) (WebAuthnCredentialInfo, error)
	List(context.Context, string) ([]WebAuthnCredentialInfo, error)
	Delete(context.Context, string, string, bool) error
}

type webAuthnService struct {
	db    *pgxpool.Pool
	redis *redis.Client
	box   *secretBox
	wa    *webauthn.WebAuthn
}

type webAuthnUser struct {
	id          []byte
	name        string
	displayName string
	credentials []webauthn.Credential
}

func (u *webAuthnUser) WebAuthnID() []byte                         { return u.id }
func (u *webAuthnUser) WebAuthnName() string                       { return u.name }
func (u *webAuthnUser) WebAuthnDisplayName() string                { return u.displayName }
func (u *webAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

type webAuthnCeremony struct {
	UserID  string               `json:"user_id"`
	Kind    string               `json:"kind"`
	Session webauthn.SessionData `json:"session"`
}

func newWebAuthnProvider(db *pgxpool.Pool, rdb *redis.Client, box *secretBox, publicURL string) (webAuthnProvider, error) {
	u, err := url.Parse(publicURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, errors.New("invalid public URL for WebAuthn")
	}
	rpID := u.Hostname()
	if rpID == "" {
		return nil, errors.New("public URL has no WebAuthn RP ID")
	}
	origin := u.Scheme + "://" + u.Host
	handler, err := webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: "OpenSSO",
		RPOrigins:     []string{origin},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationPreferred,
		},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: 2 * time.Minute, TimeoutUVD: 2 * time.Minute},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: 3 * time.Minute, TimeoutUVD: 3 * time.Minute},
		},
	})
	if err != nil {
		return nil, err
	}
	return &webAuthnService{db: db, redis: rdb, box: box, wa: handler}, nil
}

func (s *webAuthnService) BeginRegistration(ctx context.Context, userID, kind string) (WebAuthnBegin, error) {
	if kind != "security_key" && kind != "passkey" {
		return WebAuthnBegin{}, errors.New("kind must be security_key or passkey")
	}
	user, err := s.loadUser(ctx, userID, true)
	if err != nil {
		return WebAuthnBegin{}, err
	}
	selection := protocol.AuthenticatorSelection{
		UserVerification: protocol.VerificationPreferred,
		ResidentKey:      protocol.ResidentKeyRequirementDiscouraged,
	}
	if kind == "passkey" {
		selection.UserVerification = protocol.VerificationRequired
		selection.ResidentKey = protocol.ResidentKeyRequirementRequired
	}
	options, session, err := s.wa.BeginRegistration(
		user,
		webauthn.WithExclusions(webauthn.Credentials(user.credentials).CredentialDescriptors()),
		webauthn.WithAuthenticatorSelection(selection),
	)
	if err != nil {
		return WebAuthnBegin{}, err
	}
	token, err := s.storeCeremony(ctx, webAuthnCeremony{UserID: userID, Kind: "register:" + kind, Session: *session})
	if err != nil {
		return WebAuthnBegin{}, err
	}
	return WebAuthnBegin{Ceremony: token, Options: options}, nil
}

func (s *webAuthnService) FinishRegistration(ctx context.Context, userID, ceremony, displayName string, req *http.Request) (WebAuthnCredentialInfo, error) {
	state, err := s.consumeCeremony(ctx, ceremony)
	if err != nil {
		return WebAuthnCredentialInfo{}, err
	}
	if state.UserID != userID || !strings.HasPrefix(state.Kind, "register:") {
		return WebAuthnCredentialInfo{}, errors.New("WebAuthn registration ceremony does not match user")
	}
	user, err := s.loadUser(ctx, userID, false)
	if err != nil {
		return WebAuthnCredentialInfo{}, err
	}
	credential, err := s.wa.FinishRegistration(user, state.Session, req)
	if err != nil {
		return WebAuthnCredentialInfo{}, err
	}
	raw, err := json.Marshal(credential)
	if err != nil {
		return WebAuthnCredentialInfo{}, err
	}
	aad := webAuthnAAD(userID, credential.ID)
	encrypted, err := s.box.encrypt(raw, aad)
	if err != nil {
		return WebAuthnCredentialInfo{}, err
	}
	if strings.TrimSpace(displayName) == "" {
		if state.Kind == "register:passkey" {
			displayName = "Passkey"
		} else {
			displayName = "Security key"
		}
	}
	discoverable := state.Kind == "register:passkey"
	if credential.Extensions.RK != nil {
		discoverable = *credential.Extensions.RK
	}
	var id string
	var created time.Time
	err = s.db.QueryRow(ctx, `
		INSERT INTO webauthn_credentials(user_id,credential_id,encrypted_credential,display_name,discoverable)
		VALUES($1,$2,$3,$4,$5)
		RETURNING id,created_at
	`, userID, credential.ID, encrypted, strings.TrimSpace(displayName), discoverable).Scan(&id, &created)
	if err != nil {
		return WebAuthnCredentialInfo{}, err
	}
	return WebAuthnCredentialInfo{
		ID: id, DisplayName: strings.TrimSpace(displayName), Discoverable: discoverable, CreatedAt: created,
	}, nil
}

func (s *webAuthnService) BeginLogin(ctx context.Context, userID string) (WebAuthnBegin, error) {
	user, err := s.loadUser(ctx, userID, false)
	if err != nil {
		return WebAuthnBegin{}, err
	}
	if len(user.credentials) == 0 {
		return WebAuthnBegin{}, ErrNotEnrolled
	}
	options, session, err := s.wa.BeginLogin(user, webauthn.WithUserVerification(protocol.VerificationPreferred))
	if err != nil {
		return WebAuthnBegin{}, err
	}
	token, err := s.storeCeremony(ctx, webAuthnCeremony{UserID: userID, Kind: "login", Session: *session})
	if err != nil {
		return WebAuthnBegin{}, err
	}
	return WebAuthnBegin{Ceremony: token, Options: options}, nil
}

func (s *webAuthnService) FinishLogin(ctx context.Context, userID, ceremony string, req *http.Request) (WebAuthnCredentialInfo, error) {
	state, err := s.consumeCeremony(ctx, ceremony)
	if err != nil {
		return WebAuthnCredentialInfo{}, err
	}
	if state.UserID != userID || state.Kind != "login" {
		return WebAuthnCredentialInfo{}, errors.New("WebAuthn login ceremony does not match user")
	}
	user, err := s.loadUser(ctx, userID, false)
	if err != nil {
		return WebAuthnCredentialInfo{}, err
	}
	credential, err := s.wa.FinishLogin(user, state.Session, req)
	if err != nil {
		return WebAuthnCredentialInfo{}, err
	}
	raw, err := json.Marshal(credential)
	if err != nil {
		return WebAuthnCredentialInfo{}, err
	}
	encrypted, err := s.box.encrypt(raw, webAuthnAAD(userID, credential.ID))
	if err != nil {
		return WebAuthnCredentialInfo{}, err
	}
	var info WebAuthnCredentialInfo
	err = s.db.QueryRow(ctx, `
		UPDATE webauthn_credentials
		SET encrypted_credential=$1,last_used_at=now()
		WHERE user_id=$2 AND credential_id=$3
		RETURNING id,display_name,discoverable,created_at,last_used_at
	`, encrypted, userID, credential.ID).Scan(&info.ID, &info.DisplayName, &info.Discoverable, &info.CreatedAt, &info.LastUsedAt)
	if err != nil {
		return WebAuthnCredentialInfo{}, err
	}
	return info, nil
}

func (s *webAuthnService) List(ctx context.Context, userID string) ([]WebAuthnCredentialInfo, error) {
	rows, err := s.db.Query(ctx, `
		SELECT id,display_name,discoverable,created_at,last_used_at
		FROM webauthn_credentials
		WHERE user_id=$1
		ORDER BY created_at
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []WebAuthnCredentialInfo{}
	for rows.Next() {
		var item WebAuthnCredentialInfo
		if err := rows.Scan(&item.ID, &item.DisplayName, &item.Discoverable, &item.CreatedAt, &item.LastUsedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *webAuthnService) Delete(ctx context.Context, userID, id string, policyRequired bool) error {
	if policyRequired {
		var totpActive bool
		var credentials int
		if err := s.db.QueryRow(ctx, `
			SELECT
			  EXISTS(SELECT 1 FROM mfa_totp_credentials WHERE user_id=$1 AND active=true),
			  (SELECT count(*) FROM webauthn_credentials WHERE user_id=$1)
		`, userID).Scan(&totpActive, &credentials); err != nil {
			return err
		}
		if !totpActive && credentials <= 1 {
			return ErrLastRequiredFactor
		}
	}
	tag, err := s.db.Exec(ctx, `DELETE FROM webauthn_credentials WHERE id=$1 AND user_id=$2`, id, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotEnrolled
	}
	return nil
}

func (s *webAuthnService) loadUser(ctx context.Context, userID string, ensureHandle bool) (*webAuthnUser, error) {
	var username, displayName string
	if err := s.db.QueryRow(ctx, `SELECT username,display_name FROM users WHERE id=$1 AND active=true`, userID).Scan(&username, &displayName); err != nil {
		return nil, err
	}
	var handle []byte
	err := s.db.QueryRow(ctx, `SELECT user_handle FROM webauthn_users WHERE user_id=$1`, userID).Scan(&handle)
	if errors.Is(err, pgx.ErrNoRows) && ensureHandle {
		handle = make([]byte, 32)
		if _, err = rand.Read(handle); err != nil {
			return nil, err
		}
		if _, err = s.db.Exec(ctx, `INSERT INTO webauthn_users(user_id,user_handle) VALUES($1,$2) ON CONFLICT(user_id) DO NOTHING`, userID, handle); err != nil {
			return nil, err
		}
		if err = s.db.QueryRow(ctx, `SELECT user_handle FROM webauthn_users WHERE user_id=$1`, userID).Scan(&handle); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	rows, err := s.db.Query(ctx, `SELECT credential_id,encrypted_credential FROM webauthn_credentials WHERE user_id=$1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	credentials := []webauthn.Credential{}
	for rows.Next() {
		var credentialID, encrypted []byte
		if err := rows.Scan(&credentialID, &encrypted); err != nil {
			return nil, err
		}
		raw, err := s.box.decrypt(encrypted, webAuthnAAD(userID, credentialID))
		if err != nil {
			return nil, err
		}
		var credential webauthn.Credential
		if err = json.Unmarshal(raw, &credential); err != nil {
			return nil, err
		}
		credentials = append(credentials, credential)
	}
	if displayName == "" {
		displayName = username
	}
	return &webAuthnUser{id: handle, name: username, displayName: displayName, credentials: credentials}, rows.Err()
}

func (s *webAuthnService) storeCeremony(ctx context.Context, state webAuthnCeremony) (string, error) {
	token, err := security.RandomToken(24)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	key := "opensso:webauthn:ceremony:" + security.SHA256String(token)
	if err = s.redis.Set(ctx, key, payload, 5*time.Minute).Err(); err != nil {
		return "", err
	}
	return token, nil
}

func (s *webAuthnService) consumeCeremony(ctx context.Context, token string) (webAuthnCeremony, error) {
	if token == "" {
		return webAuthnCeremony{}, errors.New("missing WebAuthn ceremony token")
	}
	key := "opensso:webauthn:ceremony:" + security.SHA256String(token)
	payload, err := s.redis.GetDel(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return webAuthnCeremony{}, errors.New("WebAuthn ceremony expired or already used")
		}
		return webAuthnCeremony{}, err
	}
	var state webAuthnCeremony
	if err = json.Unmarshal(payload, &state); err != nil {
		return webAuthnCeremony{}, err
	}
	return state, nil
}

func webAuthnAAD(userID string, credentialID []byte) string {
	return fmt.Sprintf("webauthn:%s:%s", userID, base64.RawURLEncoding.EncodeToString(credentialID))
}

func (s *Service) BeginWebAuthnRegistration(ctx context.Context, userID, kind string) (WebAuthnBegin, error) {
	return s.wa.BeginRegistration(ctx, userID, kind)
}

func (s *Service) FinishWebAuthnRegistration(ctx context.Context, userID, ceremony, displayName string, req *http.Request) (WebAuthnCredentialInfo, error) {
	return s.wa.FinishRegistration(ctx, userID, ceremony, displayName, req)
}

func (s *Service) BeginWebAuthnLogin(ctx context.Context, userID string) (WebAuthnBegin, error) {
	return s.wa.BeginLogin(ctx, userID)
}

func (s *Service) FinishWebAuthnLogin(ctx context.Context, userID, ceremony string, req *http.Request) (WebAuthnCredentialInfo, error) {
	return s.wa.FinishLogin(ctx, userID, ceremony, req)
}

func (s *Service) ListWebAuthn(ctx context.Context, userID string) ([]WebAuthnCredentialInfo, error) {
	return s.wa.List(ctx, userID)
}

func (s *Service) DeleteWebAuthn(ctx context.Context, userID, id string) error {
	required, err := s.Required(ctx, userID, nil)
	if err != nil {
		return err
	}
	return s.wa.Delete(ctx, userID, id, required)
}

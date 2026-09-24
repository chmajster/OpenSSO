package mfa

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"image/png"
	"strings"
	"time"

	"github.com/chmajster/OpenSSO/backend/internal/security"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
)

var (
	ErrNotEnrolled        = errors.New("MFA factor is not enrolled")
	ErrAlreadyEnrolled    = errors.New("MFA factor is already enrolled")
	ErrInvalidCode        = errors.New("invalid MFA code")
	ErrLastRequiredFactor = errors.New("cannot remove the final MFA factor while policy requires MFA")
)

type Service struct {
	db    *pgxpool.Pool
	redis *redis.Client
	box   *secretBox
	wa    webAuthnProvider
}

type Status struct {
	Required               bool `json:"required"`
	TOTPEnabled            bool `json:"totp_enabled"`
	WebAuthnCredentials    int  `json:"webauthn_credentials"`
	Passkeys               int  `json:"passkeys"`
	RecoveryCodesRemaining int  `json:"recovery_codes_remaining"`
	HasPrimaryFactor       bool `json:"has_primary_factor"`
}

type TOTPEnrollment struct {
	Secret        string   `json:"secret"`
	OTPAuthURL    string   `json:"otpauth_url"`
	QRCodeDataURL string   `json:"qr_code_data_url"`
	RecoveryCodes []string `json:"recovery_codes,omitempty"`
}

func NewService(db *pgxpool.Pool, rdb *redis.Client, masterKey []byte, publicURL string) (*Service, error) {
	box, err := newSecretBox(masterKey)
	if err != nil {
		return nil, err
	}
	wa, err := newWebAuthnProvider(db, rdb, box, publicURL)
	if err != nil {
		return nil, err
	}
	return &Service{db: db, redis: rdb, box: box, wa: wa}, nil
}

func (s *Service) Allow(ctx context.Context, bucket, key string, limit int64, ttl time.Duration) bool {
	redisKey := "opensso:mfa:" + bucket + ":" + key
	n, err := s.redis.Incr(ctx, redisKey).Result()
	if err != nil {
		return false
	}
	if n == 1 {
		_ = s.redis.Expire(ctx, redisKey, ttl).Err()
	}
	return n <= limit
}

func (s *Service) Required(ctx context.Context, userID string, applicationID *string) (bool, error) {
	var required bool
	err := s.db.QueryRow(ctx, `
		SELECT
		  sp.mfa_required
		  OR EXISTS(
		    SELECT 1
		    FROM group_memberships gm
		    JOIN group_mfa_policies gp ON gp.group_id=gm.group_id AND gp.required=true
		    WHERE gm.user_id=$1
		  )
		  OR (
		    $2::uuid IS NOT NULL
		    AND EXISTS(
		      SELECT 1 FROM application_mfa_policies ap
		      WHERE ap.application_id=$2::uuid AND ap.required=true
		    )
		  )
		FROM security_policies sp
		WHERE sp.id=1
	`, userID, applicationID).Scan(&required)
	return required, err
}

func (s *Service) Status(ctx context.Context, userID string, applicationID *string) (Status, error) {
	var st Status
	if err := s.db.QueryRow(ctx, `
		SELECT
		  EXISTS(SELECT 1 FROM mfa_totp_credentials WHERE user_id=$1 AND active=true),
		  (SELECT count(*) FROM webauthn_credentials WHERE user_id=$1),
		  (SELECT count(*) FROM webauthn_credentials WHERE user_id=$1 AND discoverable=true),
		  (SELECT count(*) FROM mfa_recovery_codes WHERE user_id=$1 AND used_at IS NULL)
	`, userID).Scan(&st.TOTPEnabled, &st.WebAuthnCredentials, &st.Passkeys, &st.RecoveryCodesRemaining); err != nil {
		return Status{}, err
	}
	required, err := s.Required(ctx, userID, applicationID)
	if err != nil {
		return Status{}, err
	}
	st.Required = required
	st.HasPrimaryFactor = st.TOTPEnabled || st.WebAuthnCredentials > 0
	return st, nil
}

func (s *Service) BeginTOTP(ctx context.Context, userID, accountName string) (TOTPEnrollment, error) {
	var active bool
	err := s.db.QueryRow(ctx, `SELECT active FROM mfa_totp_credentials WHERE user_id=$1`, userID).Scan(&active)
	if err == nil && active {
		return TOTPEnrollment{}, ErrAlreadyEnrolled
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return TOTPEnrollment{}, err
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "OpenSSO",
		AccountName: accountName,
		Period:      30,
		SecretSize:  20,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return TOTPEnrollment{}, err
	}
	encrypted, err := s.box.encrypt([]byte(key.Secret()), "totp:"+userID)
	if err != nil {
		return TOTPEnrollment{}, err
	}
	_, err = s.db.Exec(ctx, `
		INSERT INTO mfa_totp_credentials(user_id,encrypted_secret,active,created_at,verified_at,last_used_at)
		VALUES($1,$2,false,now(),NULL,NULL)
		ON CONFLICT(user_id) DO UPDATE
		SET encrypted_secret=EXCLUDED.encrypted_secret,active=false,created_at=now(),verified_at=NULL,last_used_at=NULL
	`, userID, encrypted)
	if err != nil {
		return TOTPEnrollment{}, err
	}
	image, err := key.Image(240, 240)
	if err != nil {
		return TOTPEnrollment{}, err
	}
	var pngBuffer bytes.Buffer
	if err = png.Encode(&pngBuffer, image); err != nil {
		return TOTPEnrollment{}, err
	}
	return TOTPEnrollment{
		Secret:        key.Secret(),
		OTPAuthURL:    key.URL(),
		QRCodeDataURL: "data:image/png;base64," + base64.StdEncoding.EncodeToString(pngBuffer.Bytes()),
	}, nil
}

func (s *Service) ConfirmTOTP(ctx context.Context, userID, code string) ([]string, error) {
	secret, err := s.totpSecret(ctx, userID, false)
	if err != nil {
		return nil, err
	}
	valid, err := totp.ValidateCustom(strings.TrimSpace(code), secret, time.Now().UTC(), totp.ValidateOpts{
		Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, ErrInvalidCode
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `
		UPDATE mfa_totp_credentials
		SET active=true,verified_at=now(),last_used_at=now()
		WHERE user_id=$1
	`, userID); err != nil {
		return nil, err
	}
	var unused int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM mfa_recovery_codes WHERE user_id=$1 AND used_at IS NULL`, userID).Scan(&unused); err != nil {
		return nil, err
	}
	var codes []string
	if unused == 0 {
		codes, err = s.generateRecoveryCodesTx(ctx, tx, userID, 10)
		if err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return codes, nil
}

func (s *Service) VerifyTOTP(ctx context.Context, userID, code string) error {
	secret, err := s.totpSecret(ctx, userID, true)
	if err != nil {
		return err
	}
	valid, err := totp.ValidateCustom(strings.TrimSpace(code), secret, time.Now().UTC(), totp.ValidateOpts{
		Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return err
	}
	if !valid {
		return ErrInvalidCode
	}
	_, err = s.db.Exec(ctx, `UPDATE mfa_totp_credentials SET last_used_at=now() WHERE user_id=$1 AND active=true`, userID)
	return err
}

func (s *Service) DisableTOTP(ctx context.Context, userID string) error {
	required, err := s.Required(ctx, userID, nil)
	if err != nil {
		return err
	}
	if required {
		var other int
		if err = s.db.QueryRow(ctx, `SELECT count(*) FROM webauthn_credentials WHERE user_id=$1`, userID).Scan(&other); err != nil {
			return err
		}
		if other == 0 {
			return ErrLastRequiredFactor
		}
	}
	tag, err := s.db.Exec(ctx, `DELETE FROM mfa_totp_credentials WHERE user_id=$1`, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotEnrolled
	}
	return nil
}

func (s *Service) totpSecret(ctx context.Context, userID string, activeOnly bool) (string, error) {
	query := `SELECT encrypted_secret FROM mfa_totp_credentials WHERE user_id=$1`
	if activeOnly {
		query += ` AND active=true`
	}
	var encrypted []byte
	if err := s.db.QueryRow(ctx, query, userID).Scan(&encrypted); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrNotEnrolled
		}
		return "", err
	}
	secret, err := s.box.decrypt(encrypted, "totp:"+userID)
	if err != nil {
		return "", err
	}
	return string(secret), nil
}

func (s *Service) EnsureRecoveryCodes(ctx context.Context, userID string) ([]string, error) {
	var unused int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM mfa_recovery_codes WHERE user_id=$1 AND used_at IS NULL`, userID).Scan(&unused); err != nil {
		return nil, err
	}
	if unused > 0 {
		return nil, nil
	}
	return s.RegenerateRecoveryCodes(ctx, userID)
}

func (s *Service) RegenerateRecoveryCodes(ctx context.Context, userID string) ([]string, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE user_id=$1`, userID); err != nil {
		return nil, err
	}
	codes, err := s.generateRecoveryCodesTx(ctx, tx, userID, 10)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return codes, nil
}

func (s *Service) generateRecoveryCodesTx(ctx context.Context, tx pgx.Tx, userID string, count int) ([]string, error) {
	codes := make([]string, 0, count)
	for i := 0; i < count; i++ {
		raw := make([]byte, 10)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		compact := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
		code := strings.Join([]string{compact[0:4], compact[4:8], compact[8:12], compact[12:16]}, "-")
		hash := security.SHA256String(normalizeRecoveryCode(code))
		if _, err := tx.Exec(ctx, `INSERT INTO mfa_recovery_codes(user_id,code_hash) VALUES($1,$2)`, userID, hash); err != nil {
			return nil, err
		}
		codes = append(codes, code)
	}
	return codes, nil
}

func normalizeRecoveryCode(code string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
}

func (s *Service) VerifyRecoveryCode(ctx context.Context, userID, code string) error {
	hash := security.SHA256String(normalizeRecoveryCode(code))
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var id string
	var usedAt *time.Time
	err = tx.QueryRow(ctx, `
		SELECT id,used_at
		FROM mfa_recovery_codes
		WHERE user_id=$1 AND code_hash=$2
		FOR UPDATE
	`, userID, hash).Scan(&id, &usedAt)
	if err != nil || usedAt != nil {
		return ErrInvalidCode
	}
	if _, err = tx.Exec(ctx, `UPDATE mfa_recovery_codes SET used_at=now() WHERE id=$1`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Service) ResetUser(ctx context.Context, userID string) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, stmt := range []string{
		`DELETE FROM mfa_totp_credentials WHERE user_id=$1`,
		`DELETE FROM mfa_recovery_codes WHERE user_id=$1`,
		`DELETE FROM webauthn_credentials WHERE user_id=$1`,
		`DELETE FROM webauthn_users WHERE user_id=$1`,
		`UPDATE sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL`,
	} {
		if _, err = tx.Exec(ctx, stmt, userID); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Service) SetGlobalPolicy(ctx context.Context, required bool) error {
	_, err := s.db.Exec(ctx, `UPDATE security_policies SET mfa_required=$1,updated_at=now() WHERE id=1`, required)
	return err
}

func (s *Service) SetGroupPolicy(ctx context.Context, groupID string, required bool) error {
	if !required {
		_, err := s.db.Exec(ctx, `DELETE FROM group_mfa_policies WHERE group_id=$1`, groupID)
		return err
	}
	_, err := s.db.Exec(ctx, `
		INSERT INTO group_mfa_policies(group_id,required) VALUES($1,true)
		ON CONFLICT(group_id) DO UPDATE SET required=true,updated_at=now()
	`, groupID)
	return err
}

func (s *Service) SetApplicationPolicy(ctx context.Context, applicationID string, required bool) error {
	if !required {
		_, err := s.db.Exec(ctx, `DELETE FROM application_mfa_policies WHERE application_id=$1`, applicationID)
		return err
	}
	_, err := s.db.Exec(ctx, `
		INSERT INTO application_mfa_policies(application_id,required) VALUES($1,true)
		ON CONFLICT(application_id) DO UPDATE SET required=true,updated_at=now()
	`, applicationID)
	return err
}

func (s *Service) GroupPolicy(ctx context.Context, groupID string) (bool, error) {
	var required bool
	err := s.db.QueryRow(ctx, `SELECT COALESCE((SELECT required FROM group_mfa_policies WHERE group_id=$1),false)`, groupID).Scan(&required)
	return required, err
}

func (s *Service) ApplicationPolicy(ctx context.Context, applicationID string) (bool, error) {
	var required bool
	err := s.db.QueryRow(ctx, `SELECT COALESCE((SELECT required FROM application_mfa_policies WHERE application_id=$1),false)`, applicationID).Scan(&required)
	return required, err
}

func (s *Service) VerifyFactor(ctx context.Context, userID, method, code string) error {
	switch method {
	case "totp":
		return s.VerifyTOTP(ctx, userID, code)
	case "recovery":
		return s.VerifyRecoveryCode(ctx, userID, code)
	default:
		return fmt.Errorf("unsupported MFA method")
	}
}

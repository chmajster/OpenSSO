package samlidp

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"time"

	"github.com/chmajster/OpenSSO/backend/internal/security"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zitadel/saml/pkg/provider/key"
)

type CertificateManager struct {
	db        *pgxpool.Pool
	masterKey []byte
}

func NewCertificateManager(db *pgxpool.Pool, masterKey []byte) *CertificateManager {
	return &CertificateManager{db: db, masterKey: append([]byte(nil), masterKey...)}
}

func (m *CertificateManager) Active(ctx context.Context) (*key.CertificateAndKey, error) {
	var kid string
	var encrypted, certDER []byte
	var notAfter time.Time
	err := m.db.QueryRow(ctx, `
		SELECT kid,encrypted_private_key,certificate_der,not_after
		FROM saml_signing_certificates
		WHERE active=true
		LIMIT 1
	`).Scan(&kid, &encrypted, &certDER, &notAfter)
	if err == nil {
		if time.Until(notAfter) < 30*24*time.Hour {
			return m.Rotate(ctx)
		}
		privateKey, err := m.decryptPrivateKey(kid, encrypted)
		if err != nil {
			return nil, err
		}
		return &key.CertificateAndKey{Certificate: certDER, Key: privateKey}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	return m.Rotate(ctx)
}

func (m *CertificateManager) Rotate(ctx context.Context) (*key.CertificateAndKey, error) {
	tx, err := m.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('opensso-saml-signing-certificate'))`); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `UPDATE saml_signing_certificates SET active=false,retired_at=now() WHERE active=true`); err != nil {
		return nil, err
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	notBefore := now.Add(-5 * time.Minute)
	notAfter := now.AddDate(2, 0, 0)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "OpenSSO SAML Signing",
			Organization: []string{"OpenSSO"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}
	kid, err := security.RandomToken(12)
	if err != nil {
		return nil, err
	}
	encrypted, err := m.encryptPrivateKey(kid, privateKey)
	if err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `
		INSERT INTO saml_signing_certificates(
			kid,encrypted_private_key,certificate_der,not_before,not_after,active
		) VALUES($1,$2,$3,$4,$5,true)
	`, kid, encrypted, certDER, notBefore, notAfter); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &key.CertificateAndKey{Certificate: certDER, Key: privateKey}, nil
}

func (m *CertificateManager) Metadata(ctx context.Context) ([]map[string]any, error) {
	rows, err := m.db.Query(ctx, `
		SELECT kid,active,not_before,not_after,created_at,retired_at
		FROM saml_signing_certificates
		ORDER BY active DESC,created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var kid string
		var active bool
		var notBefore, notAfter, created time.Time
		var retired *time.Time
		if err := rows.Scan(&kid, &active, &notBefore, &notAfter, &created, &retired); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{
			"kid": kid, "active": active, "not_before": notBefore,
			"not_after": notAfter, "created_at": created, "retired_at": retired,
		})
	}
	return items, rows.Err()
}

func (m *CertificateManager) encryptPrivateKey(kid string, privateKey *rsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	gcm, err := m.gcm()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	return append(nonce, gcm.Seal(nil, nonce, der, []byte("saml:"+kid))...), nil
}

func (m *CertificateManager) decryptPrivateKey(kid string, encrypted []byte) (*rsa.PrivateKey, error) {
	gcm, err := m.gcm()
	if err != nil {
		return nil, err
	}
	if len(encrypted) <= gcm.NonceSize() {
		return nil, errors.New("invalid encrypted SAML private key")
	}
	nonce, ciphertext := encrypted[:gcm.NonceSize()], encrypted[gcm.NonceSize():]
	der, err := gcm.Open(nil, nonce, ciphertext, []byte("saml:"+kid))
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	privateKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("stored SAML private key is not RSA")
	}
	return privateKey, nil
}

func (m *CertificateManager) gcm() (cipher.AEAD, error) {
	block, err := aes.NewCipher(m.masterKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

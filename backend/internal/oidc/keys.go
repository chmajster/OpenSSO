package oidc

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"

	"github.com/chmajster/OpenSSO/backend/internal/security"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SigningKey struct {
	Kid        string
	PrivateKey *rsa.PrivateKey
}

type KeyManager struct {
	db        *pgxpool.Pool
	masterKey []byte
}

func NewKeyManager(db *pgxpool.Pool, masterKey []byte) *KeyManager {
	return &KeyManager{db: db, masterKey: append([]byte(nil), masterKey...)}
}

func (m *KeyManager) Active(ctx context.Context) (*SigningKey, error) {
	var kid string
	var encrypted []byte
	err := m.db.QueryRow(ctx, `SELECT kid,encrypted_private_key FROM signing_keys WHERE active=true LIMIT 1`).Scan(&kid, &encrypted)
	if err == nil {
		key, err := m.decryptPrivateKey(kid, encrypted)
		if err != nil {
			return nil, err
		}
		return &SigningKey{Kid: kid, PrivateKey: key}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	return m.Rotate(ctx)
}

func (m *KeyManager) Rotate(ctx context.Context) (*SigningKey, error) {
	tx, err := m.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('opensso-signing-key'))`); err != nil {
		return nil, err
	}
	var currentKid string
	var currentEncrypted []byte
	err = tx.QueryRow(ctx, `SELECT kid,encrypted_private_key FROM signing_keys WHERE active=true LIMIT 1`).Scan(&currentKid, &currentEncrypted)
	if err == nil {
		if _, err = tx.Exec(ctx, `UPDATE signing_keys SET active=false,retired_at=now() WHERE active=true`); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 3072)
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
	publicJWK, err := json.Marshal(jwkFromPublicKey(kid, &privateKey.PublicKey))
	if err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `
		INSERT INTO signing_keys(kid,algorithm,encrypted_private_key,public_jwk,active)
		VALUES($1,'RS256',$2,$3::jsonb,true)
	`, kid, encrypted, string(publicJWK)); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &SigningKey{Kid: kid, PrivateKey: privateKey}, nil
}

func (m *KeyManager) JWKS(ctx context.Context) ([]map[string]any, error) {
	rows, err := m.db.Query(ctx, `SELECT public_jwk FROM signing_keys ORDER BY active DESC,created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := []map[string]any{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var key map[string]any
		if err := json.Unmarshal(raw, &key); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (m *KeyManager) PublicKeyByKID(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	var raw []byte
	if err := m.db.QueryRow(ctx, `SELECT public_jwk FROM signing_keys WHERE kid=$1`, kid).Scan(&raw); err != nil {
		return nil, err
	}
	var jwk struct {
		Kty string `json:"kty"`
		N   string `json:"n"`
		E   string `json:"e"`
	}
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return nil, err
	}
	if jwk.Kty != "RSA" {
		return nil, errors.New("unsupported signing key type")
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}
	if e < 3 {
		return nil, errors.New("invalid RSA exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}

func (m *KeyManager) encryptPrivateKey(kid string, key *rsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
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
	return append(nonce, gcm.Seal(nil, nonce, der, []byte(kid))...), nil
}

func (m *KeyManager) decryptPrivateKey(kid string, encrypted []byte) (*rsa.PrivateKey, error) {
	gcm, err := m.gcm()
	if err != nil {
		return nil, err
	}
	if len(encrypted) <= gcm.NonceSize() {
		return nil, errors.New("invalid encrypted private key")
	}
	nonce, ciphertext := encrypted[:gcm.NonceSize()], encrypted[gcm.NonceSize():]
	der, err := gcm.Open(nil, nonce, ciphertext, []byte(kid))
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("stored private key is not RSA")
	}
	return key, nil
}

func (m *KeyManager) gcm() (cipher.AEAD, error) {
	block, err := aes.NewCipher(m.masterKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func jwkFromPublicKey(kid string, key *rsa.PublicKey) map[string]any {
	e := big.NewInt(int64(key.E)).Bytes()
	return map[string]any{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": kid,
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(e),
	}
}

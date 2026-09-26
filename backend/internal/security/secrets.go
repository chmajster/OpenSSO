package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

const encryptedSecretVersion byte = 1

// EncryptSecret encrypts application secrets with AES-256-GCM using the
// installation master key. The returned value is versioned so the storage
// format can be migrated without guessing the cipher layout.
func EncryptSecret(masterKey, plaintext []byte) ([]byte, error) {
	if len(masterKey) != 32 {
		return nil, errors.New("master key must be 32 bytes")
	}
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 1, 1+len(nonce)+len(plaintext)+gcm.Overhead())
	out[0] = encryptedSecretVersion
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, plaintext, nil)
	return out, nil
}

// DecryptSecret authenticates and decrypts a value produced by EncryptSecret.
func DecryptSecret(masterKey, ciphertext []byte) ([]byte, error) {
	if len(masterKey) != 32 {
		return nil, errors.New("master key must be 32 bytes")
	}
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < 1+gcm.NonceSize()+gcm.Overhead() || ciphertext[0] != encryptedSecretVersion {
		return nil, errors.New("invalid encrypted secret")
	}
	nonce := ciphertext[1 : 1+gcm.NonceSize()]
	encrypted := ciphertext[1+gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, errors.New("encrypted secret authentication failed")
	}
	return plain, nil
}

package mfa

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

type secretBox struct {
	key []byte
}

func newSecretBox(key []byte) (*secretBox, error) {
	if len(key) != 32 {
		return nil, errors.New("MFA master key must contain exactly 32 bytes")
	}
	return &secretBox{key: append([]byte(nil), key...)}, nil
}

func (b *secretBox) encrypt(plaintext []byte, aad string) ([]byte, error) {
	block, err := aes.NewCipher(b.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	return append(nonce, gcm.Seal(nil, nonce, plaintext, []byte(aad))...), nil
}

func (b *secretBox) decrypt(ciphertext []byte, aad string) ([]byte, error) {
	block, err := aes.NewCipher(b.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) <= gcm.NonceSize() {
		return nil, errors.New("invalid encrypted MFA value")
	}
	nonce := ciphertext[:gcm.NonceSize()]
	payload := ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, payload, []byte(aad))
}

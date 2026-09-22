package oidc

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestPrivateKeyEncryptionRoundTrip(t *testing.T) {
	master := bytes.Repeat([]byte{0x42}, 32)
	manager := &KeyManager{masterKey: master}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := manager.encryptPrivateKey("kid-test", key)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, key.D.Bytes()) {
		t.Fatal("encrypted representation unexpectedly contains private exponent")
	}
	decoded, err := manager.decryptPrivateKey("kid-test", encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.N.Cmp(key.N) != 0 || decoded.D.Cmp(key.D) != 0 {
		t.Fatal("decrypted private key does not match original")
	}
	if _, err := manager.decryptPrivateKey("different-kid", encrypted); err == nil {
		t.Fatal("AAD mismatch should fail decryption")
	}
}

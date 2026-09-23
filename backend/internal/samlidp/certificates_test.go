package samlidp

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestSAMLPrivateKeyEncryptionRoundTrip(t *testing.T) {
	manager := &CertificateManager{masterKey: bytes.Repeat([]byte{0x31}, 32)}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := manager.encryptPrivateKey("test-kid", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, privateKey.D.Bytes()) {
		t.Fatal("encrypted SAML private key contains private exponent")
	}
	decoded, err := manager.decryptPrivateKey("test-kid", encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.N.Cmp(privateKey.N) != 0 || decoded.D.Cmp(privateKey.D) != 0 {
		t.Fatal("decrypted SAML private key differs from original")
	}
	if _, err := manager.decryptPrivateKey("other-kid", encrypted); err == nil {
		t.Fatal("different AAD kid must reject ciphertext")
	}
}

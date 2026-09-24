package mfa

import (
	"bytes"
	"testing"
)

func TestSecretBoxRoundTripAndAAD(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	box, err := newSecretBox(key)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("mfa-secret-value")
	ciphertext, err := box.encrypt(plaintext, "totp:user-1")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, plaintext) {
		t.Fatal("ciphertext unexpectedly contains plaintext")
	}
	decoded, err := box.decrypt(ciphertext, "totp:user-1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, plaintext) {
		t.Fatal("decrypted plaintext does not match")
	}
	if _, err := box.decrypt(ciphertext, "totp:other-user"); err == nil {
		t.Fatal("AAD mismatch must fail")
	}
}

func TestSecretBoxRequires32ByteKey(t *testing.T) {
	if _, err := newSecretBox([]byte("short")); err == nil {
		t.Fatal("expected invalid master-key length error")
	}
}

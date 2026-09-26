package security

import (
	"bytes"
	"testing"
)

func TestSecretEncryptionRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	plain := []byte("directory-bind-secret")
	encrypted, err := EncryptSecret(key, plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, plain) {
		t.Fatal("ciphertext contains plaintext")
	}
	got, err := DecryptSecret(key, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("got %q", got)
	}
	encrypted[len(encrypted)-1] ^= 1
	if _, err = DecryptSecret(key, encrypted); err == nil {
		t.Fatal("tampered ciphertext was accepted")
	}
}

func TestSecretEncryptionRejectsWrongKey(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	encrypted, err := EncryptSecret(key, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	wrong := bytes.Repeat([]byte{2}, 32)
	if _, err = DecryptSecret(wrong, encrypted); err == nil {
		t.Fatal("wrong key was accepted")
	}
}

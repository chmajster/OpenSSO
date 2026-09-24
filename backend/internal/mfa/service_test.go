package mfa

import "testing"

func TestNormalizeRecoveryCode(t *testing.T) {
	got := normalizeRecoveryCode(" abcd-efgh-Ijkl-mnop ")
	if got != "ABCDEFGHIJKLMNOP" {
		t.Fatalf("unexpected normalized recovery code: %q", got)
	}
}

func TestWebAuthnConfigurationAcceptsLocalhostAndRejectsIPRPID(t *testing.T) {
	key := make([]byte, 32)
	box, err := newSecretBox(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newWebAuthnProvider(nil, nil, box, "http://localhost:8080"); err != nil {
		t.Fatalf("localhost should be a valid WebAuthn development RP: %v", err)
	}
	if _, err := newWebAuthnProvider(nil, nil, box, "http://127.0.0.1:8080"); err == nil {
		t.Fatal("IP address RP ID should be rejected by WebAuthn configuration")
	}
}

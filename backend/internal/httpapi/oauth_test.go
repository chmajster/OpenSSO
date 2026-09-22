package httpapi

import "testing"

func TestPKCES256RFC7636Vector(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if !validPKCEVerifier(verifier) {
		t.Fatal("RFC7636 verifier should be valid")
	}
	if !verifyPKCE(verifier, challenge) {
		t.Fatal("RFC7636 S256 vector did not verify")
	}
	if verifyPKCE(verifier+"x", challenge) {
		t.Fatal("modified verifier unexpectedly verified")
	}
}

func TestScopeNormalizationAndSubset(t *testing.T) {
	scope, scopes, err := normalizeRequestedScope("openid profile openid email")
	if err != nil {
		t.Fatal(err)
	}
	if scope != "openid profile email" {
		t.Fatalf("unexpected normalized scope: %q", scope)
	}
	if !containsAll([]string{"openid", "profile", "email"}, scopes) {
		t.Fatal("expected requested scopes to be allowed")
	}
	if containsAll([]string{"openid"}, scopes) {
		t.Fatal("expected missing scopes to be rejected")
	}
}

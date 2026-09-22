package security

import "testing"

func TestPasswordRoundTrip(t *testing.T) {
	h, e := HashPassword("this-is-a-long-test-password")
	if e != nil {
		t.Fatal(e)
	}
	if !VerifyPassword(h, "this-is-a-long-test-password") {
		t.Fatal("expected password verification to succeed")
	}
	if VerifyPassword(h, "wrong-password-value") {
		t.Fatal("expected password verification to fail")
	}
}
func TestPasswordMinimumLength(t *testing.T) {
	if _, e := HashPassword("short"); e == nil {
		t.Fatal("expected minimum length error")
	}
}

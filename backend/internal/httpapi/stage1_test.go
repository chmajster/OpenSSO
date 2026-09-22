package httpapi

import "testing"

func TestPasswordPolicyViolation(t *testing.T) {
	policy := securityPolicy{
		PasswordMinLength:     12,
		PasswordRequireUpper:  true,
		PasswordRequireLower:  true,
		PasswordRequireDigit:  true,
		PasswordRequireSymbol: true,
	}
	cases := []struct {
		name     string
		password string
		valid    bool
	}{
		{"valid", "Strong-Password-123!", true},
		{"too short", "Aa1!", false},
		{"no uppercase", "lowercase-123!", false},
		{"no lowercase", "UPPERCASE-123!", false},
		{"no digit", "Password-With-Symbol!", false},
		{"no symbol", "PasswordWithDigit123", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := passwordPolicyViolation(policy, tc.password)
			if tc.valid && got != "" {
				t.Fatalf("expected valid password, got %q", got)
			}
			if !tc.valid && got == "" {
				t.Fatal("expected policy violation")
			}
		})
	}
}

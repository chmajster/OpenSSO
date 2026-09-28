package httpapi

import "testing"

func TestNormalizeLoginUISettings(t *testing.T) {
	in := defaultLoginUISettings()
	in.Enabled = true
	in.BrandName = "  Example Corp  "
	in.LogoURL = "https://login.example.test/logo.svg"
	out, err := normalizeLoginUISettings(in)
	if err != nil {
		t.Fatalf("normalizeLoginUISettings returned error: %v", err)
	}
	if out.BrandName != "Example Corp" {
		t.Fatalf("expected trimmed brand name, got %q", out.BrandName)
	}
}

func TestNormalizeLoginUIRejectsUnsafeURL(t *testing.T) {
	in := defaultLoginUISettings()
	in.LogoURL = "javascript:alert(1)"
	if _, err := normalizeLoginUISettings(in); err == nil {
		t.Fatal("expected unsafe URL to be rejected")
	}
}

func TestNormalizeLoginUIRejectsInvalidColor(t *testing.T) {
	in := defaultLoginUISettings()
	in.PrimaryColor = "red"
	if _, err := normalizeLoginUISettings(in); err == nil {
		t.Fatal("expected invalid color to be rejected")
	}
}

func TestNormalizeLoginUIAllowsRootRelativeMedia(t *testing.T) {
	in := defaultLoginUISettings()
	in.BackgroundImageURL = "/branding/login-background.webp"
	if _, err := normalizeLoginUISettings(in); err != nil {
		t.Fatalf("expected root-relative media URL to be accepted: %v", err)
	}
}

func TestNormalizeLoginUIRejectsMalformedRootRelativeMedia(t *testing.T) {
	in := defaultLoginUISettings()
	in.LogoURL = "/logo.svg\");background-image:url(https://example.test/x)"
	if _, err := normalizeLoginUISettings(in); err == nil {
		t.Fatal("expected malformed root-relative media URL to be rejected")
	}
}

func TestNormalizeLoginUIAcceptsUnicodeWithinCharacterLimit(t *testing.T) {
	in := defaultLoginUISettings()
	in.BrandName = "Zażółć gęślą jaźń"
	if _, err := normalizeLoginUISettings(in); err != nil {
		t.Fatalf("expected Unicode branding to be accepted: %v", err)
	}
}

func TestNormalizeLoginUIRejectsOversizedMediaURL(t *testing.T) {
	in := defaultLoginUISettings()
	in.LogoURL = "https://example.test/" + string(make([]byte, 2050))
	if _, err := normalizeLoginUISettings(in); err == nil {
		t.Fatal("expected oversized media URL to be rejected")
	}
}

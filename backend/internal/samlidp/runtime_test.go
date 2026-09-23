package samlidp

import "testing"

func TestValidateServiceProviderMetadata(t *testing.T) {
	valid := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.test/metadata">
<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.test/acs" index="0"/>
</SPSSODescriptor></EntityDescriptor>`
	entityID, err := ValidateServiceProviderMetadata(valid)
	if err != nil {
		t.Fatal(err)
	}
	if entityID != "https://sp.example.test/metadata" {
		t.Fatalf("unexpected entityID %q", entityID)
	}

	cases := []string{
		"",
		`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID=""></EntityDescriptor>`,
		`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.test/metadata"><SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://sp.example.test/acs" index="0"/></SPSSODescriptor></EntityDescriptor>`,
	}
	for _, metadata := range cases {
		if _, err := ValidateServiceProviderMetadata(metadata); err == nil {
			t.Fatalf("expected metadata validation failure for %q", metadata)
		}
	}
}

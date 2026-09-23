package main

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/zitadel/saml/pkg/provider"
	"github.com/zitadel/saml/pkg/provider/signature"
	samlxml "github.com/zitadel/saml/pkg/provider/xml"
	"github.com/zitadel/saml/pkg/provider/xml/saml"
	"github.com/zitadel/saml/pkg/provider/xml/samlp"
)

const rsaSHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

var hiddenInput = regexp.MustCompile(`(?s)name="([^"]+)"\s+value="([^"]*)"`)

func main() {
	baseURL := flag.String("base-url", "http://127.0.0.1:8080", "OpenSSO base URL")
	username := flag.String("username", "e2e-admin", "OpenSSO test username")
	password := flag.String("password", "", "OpenSSO test password")
	flag.Parse()
	if *password == "" {
		fatal(errors.New("--password is required"))
	}
	if err := run(strings.TrimRight(*baseURL, "/"), *username, *password); err != nil {
		fatal(err)
	}
	fmt.Println("OpenSSO SAML 2.0 E2E flow passed.")
}

func run(baseURL, username, password string) error {
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if err := login(client, baseURL, username, password); err != nil {
		return err
	}
	me, err := getJSON(client, baseURL+"/api/v1/me")
	if err != nil {
		return err
	}
	userID := stringField(me, "UserID")
	if userID == "" {
		userID = stringField(me, "user_id")
	}
	if userID == "" {
		return errors.New("current user ID missing")
	}

	spKey, spCertDER, err := generateCertificate("OpenSSO E2E SAML SP")
	if err != nil {
		return err
	}
	spEntityID := "https://sp.example.test/metadata"
	acsURL := "https://sp.example.test/acs"
	spMetadata := buildSPMetadata(spEntityID, acsURL, spCertDER, true)

	created, err := postJSON(client, baseURL, "/api/v1/saml/applications", map[string]any{
		"name":                         "E2E SAML Client",
		"initiate_login_uri":           "https://sp.example.test/login",
		"metadata_xml":                 spMetadata,
		"require_signed_authn_request": true,
	})
	if err != nil {
		return fmt.Errorf("create SAML application: %w", err)
	}
	appID := stringField(created, "id")
	if appID == "" {
		return errors.New("SAML application ID missing")
	}
	if _, err = postJSON(client, baseURL, "/api/v1/applications/"+appID+"/assign/users", map[string]any{"user_id": userID}); err != nil {
		return fmt.Errorf("assign SAML application: %w", err)
	}

	integration, err := getJSON(client, baseURL+"/api/v1/saml/applications/"+appID+"/integration")
	if err != nil {
		return err
	}
	if stringField(integration, "sp_entity_id") != spEntityID {
		return errors.New("SAML integration entityID mismatch")
	}
	idpEntityID := stringField(integration, "idp_entity_id")
	ssoURL := stringField(integration, "sso_url")
	metadataURL := stringField(integration, "idp_metadata_url")
	if idpEntityID == "" || ssoURL == "" || metadataURL == "" {
		return errors.New("SAML integration details incomplete")
	}

	idpMetadataXML, err := getBytes(client, metadataURL)
	if err != nil {
		return err
	}
	if bytes.Contains(idpMetadataXML, []byte("SingleLogoutService")) || bytes.Contains(idpMetadataXML, []byte("AttributeAuthorityDescriptor")) {
		return errors.New("IdP metadata advertises unsupported SAML surfaces")
	}
	idpCert, err := certificateFromMetadata(idpMetadataXML)
	if err != nil {
		return err
	}
	if err = validateXMLSignature(idpMetadataXML, idpCert, "EntityDescriptor"); err != nil {
		return fmt.Errorf("IdP metadata signature: %w", err)
	}

	requestID := "_opensso_e2e_signed_authn_request"
	relayState := "opensso-e2e-relay"
	signedURL, err := authnRequestURL(ssoURL, spEntityID, acsURL, requestID, relayState, spKey, spCertDER, true)
	if err != nil {
		return err
	}
	resp, err := client.Get(signedURL)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return fmt.Errorf("expected SAML SSO login redirect, got %d", resp.StatusCode)
	}
	location := resp.Header.Get("Location")
	redirectURL, err := url.Parse(location)
	if err != nil {
		return err
	}
	requestKey := redirectURL.Query().Get("saml_request_id")
	if requestKey == "" {
		return fmt.Errorf("SAML continuation request ID missing from redirect %q", location)
	}

	continuation, err := postJSON(client, baseURL, "/api/v1/saml/continue", map[string]any{"request_id": requestKey})
	if err != nil {
		return fmt.Errorf("continue SAML authentication: %w", err)
	}
	callbackURL := stringField(continuation, "callback_url")
	if callbackURL == "" {
		return errors.New("SAML callback URL missing")
	}

	formHTML, err := getBytes(client, callbackURL)
	if err != nil {
		return err
	}
	form := parseHiddenInputs(string(formHTML))
	if form["RelayState"] != relayState {
		return fmt.Errorf("RelayState mismatch: %q", form["RelayState"])
	}
	samlResponse := form["SAMLResponse"]
	if samlResponse == "" {
		return errors.New("SAMLResponse missing from POST form")
	}
	responseXML, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		return fmt.Errorf("decode SAMLResponse: %w", err)
	}
	if err = validateXMLSignature(responseXML, idpCert, "Response"); err != nil {
		return fmt.Errorf("SAML Response signature: %w", err)
	}
	if err = validateXMLSignature(responseXML, idpCert, "Assertion"); err != nil {
		return fmt.Errorf("SAML Assertion signature: %w", err)
	}
	typed, err := samlxml.DecodeResponse("", false, string(responseXML))
	if err != nil {
		return err
	}
	if err = validateResponse(typed, requestID, idpEntityID, spEntityID, acsURL, username); err != nil {
		return err
	}

	// The callback consumes the persisted request atomically. A replay must
	// not produce another successful SAML POST form.
	replay, err := getBytes(client, callbackURL)
	if err != nil {
		return err
	}
	if strings.Contains(string(replay), `name="SAMLResponse"`) {
		replayFields := parseHiddenInputs(string(replay))
		if raw := replayFields["SAMLResponse"]; raw != "" {
			xmlBytes, decErr := base64.StdEncoding.DecodeString(raw)
			if decErr == nil && bytes.Contains(xmlBytes, []byte("status:Success")) {
				return errors.New("SAML callback replay produced success")
			}
		}
	}

	// Configured signed-request requirement must reject an unsigned request.
	unsignedURL, err := authnRequestURL(ssoURL, spEntityID, acsURL, "_opensso_e2e_unsigned", "unsigned", spKey, spCertDER, false)
	if err != nil {
		return err
	}
	unsignedResp, err := client.Get(unsignedURL)
	if err != nil {
		return err
	}
	unsignedBody, _ := io.ReadAll(unsignedResp.Body)
	unsignedResp.Body.Close()
	if unsignedResp.StatusCode >= 300 && unsignedResp.StatusCode < 400 {
		return errors.New("unsigned AuthnRequest unexpectedly reached login continuation")
	}
	if len(unsignedBody) == 0 {
		return errors.New("unsigned AuthnRequest rejection had empty response")
	}

	// Exact ACS validation: a signed request cannot override the registered ACS.
	badACSURL, err := authnRequestURL(ssoURL, spEntityID, "https://attacker.example.test/acs", "_opensso_e2e_bad_acs", "bad-acs", spKey, spCertDER, true)
	if err != nil {
		return err
	}
	badACSResp, err := client.Get(badACSURL)
	if err != nil {
		return err
	}
	badACSBody, _ := io.ReadAll(badACSResp.Body)
	badACSResp.Body.Close()
	if badACSResp.StatusCode >= 300 && badACSResp.StatusCode < 400 {
		return errors.New("mismatched ACS unexpectedly reached login continuation")
	}
	if len(badACSBody) == 0 {
		return errors.New("mismatched ACS rejection had empty response")
	}

	// A request ID is unique and cannot be inserted twice.
	replayURL, err := authnRequestURL(ssoURL, spEntityID, acsURL, requestID, relayState, spKey, spCertDER, true)
	if err != nil {
		return err
	}
	requestReplayResp, err := client.Get(replayURL)
	if err != nil {
		return err
	}
	requestReplayBody, _ := io.ReadAll(requestReplayResp.Body)
	requestReplayResp.Body.Close()
	if requestReplayResp.StatusCode >= 300 && requestReplayResp.StatusCode < 400 {
		return errors.New("replayed AuthnRequest ID unexpectedly reached login continuation")
	}
	if len(requestReplayBody) == 0 {
		return errors.New("replayed AuthnRequest rejection had empty response")
	}

	return nil
}

func login(client *http.Client, baseURL, username, password string) error {
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("login failed: %d %s", resp.StatusCode, data)
	}
	return nil
}

func csrfToken(client *http.Client, baseURL string) string {
	u, _ := url.Parse(baseURL)
	for _, c := range client.Jar.Cookies(u) {
		if c.Name == "opensso_csrf" {
			return c.Value
		}
	}
	return ""
}

func postJSON(client *http.Client, baseURL, path string, value any) (map[string]any, error) {
	body, _ := json.Marshal(value)
	req, _ := http.NewRequest(http.MethodPost, baseURL+path, bytes.NewReader(body))
	if strings.Contains(path, "/saml/applications/") && strings.HasPrefix(path, "/api/v1/saml/applications/") {
		req.Method = http.MethodPut
	}
	req.Header.Set("Content-Type", "application/json")
	if token := csrfToken(client, baseURL); token != "" {
		req.Header.Set("X-CSRF-Token", token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s %s returned %d: %s", req.Method, path, resp.StatusCode, data)
	}
	if len(data) == 0 {
		return map[string]any{}, nil
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func getJSON(client *http.Client, target string) (map[string]any, error) {
	data, err := getBytes(client, target)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func getBytes(client *http.Client, target string) ([]byte, error) {
	resp, err := client.Get(target)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GET %s returned %d: %s", target, resp.StatusCode, data)
	}
	return data, nil
}

func generateCertificate(commonName string) (*rsa.PrivateKey, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	return key, der, err
}

func buildSPMetadata(entityID, acsURL string, certDER []byte, signed bool) string {
	signedValue := "false"
	if signed {
		signedValue = "true"
	}
	cert := base64.StdEncoding.EncodeToString(certDER)
	return fmt.Sprintf(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="%s" WantAssertionsSigned="true">
<KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>%s</X509Certificate></X509Data></KeyInfo></KeyDescriptor>
<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s" index="0" isDefault="true"/>
</SPSSODescriptor></EntityDescriptor>`, entityID, signedValue, cert, acsURL)
}

func authnRequestURL(
	ssoURL, entityID, acsURL, requestID, relayState string,
	key *rsa.PrivateKey, certDER []byte, sign bool,
) (string, error) {
	request := &samlp.AuthnRequestType{
		Id:                          requestID,
		Version:                     "2.0",
		IssueInstant:                time.Now().UTC().Format(time.RFC3339Nano),
		Destination:                 ssoURL,
		ProtocolBinding:             provider.PostBinding,
		AssertionConsumerServiceURL: acsURL,
		Issuer: &saml.NameIDType{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Text:   entityID,
		},
		NameIDPolicy: &samlp.NameIDPolicyType{
			Format:      "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
			AllowCreate: true,
		},
	}
	raw, err := samlxml.Marshal(request)
	if err != nil {
		return "", err
	}
	compressed, err := deflateAndBase64(raw)
	if err != nil {
		return "", err
	}
	query := "SAMLRequest=" + url.QueryEscape(compressed)
	if relayState != "" {
		query += "&RelayState=" + url.QueryEscape(relayState)
	}
	if sign {
		query += "&SigAlg=" + url.QueryEscape(rsaSHA256)
		tlsCert, err := signature.ParseTlsKeyPair(certDER, key)
		if err != nil {
			return "", err
		}
		signingContext, err := signature.GetSigningContext(tlsCert, rsaSHA256)
		if err != nil {
			return "", err
		}
		sig, err := signature.CreateRedirect(signingContext, query)
		if err != nil {
			return "", err
		}
		query += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	}
	return ssoURL + "?" + query, nil
}

func deflateAndBase64(data []byte) (string, error) {
	var compressed bytes.Buffer
	writer, err := flate.NewWriter(&compressed, flate.BestCompression)
	if err != nil {
		return "", err
	}
	if _, err = writer.Write(data); err != nil {
		return "", err
	}
	if err = writer.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(compressed.Bytes()), nil
}

func parseHiddenInputs(page string) map[string]string {
	out := map[string]string{}
	for _, match := range hiddenInput.FindAllStringSubmatch(page, -1) {
		out[match[1]] = html.UnescapeString(match[2])
	}
	return out
}

func certificateFromMetadata(metadata []byte) (*x509.Certificate, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(metadata); err != nil {
		return nil, err
	}
	element := doc.FindElement(".//X509Certificate")
	if element == nil {
		return nil, errors.New("X509Certificate missing from IdP metadata")
	}
	raw := strings.Join(strings.Fields(element.Text()), "")
	der, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func validateXMLSignature(data []byte, cert *x509.Certificate, elementName string) error {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(data); err != nil {
		return err
	}
	var element *etree.Element
	if doc.Root() != nil && doc.Root().Tag == elementName {
		element = doc.Root()
	} else {
		element = doc.FindElement(".//" + elementName)
	}
	if element == nil {
		return fmt.Errorf("%s element missing", elementName)
	}
	return signature.ValidatePost([]*x509.Certificate{cert}, element)
}

func validateResponse(
	response *samlp.ResponseType,
	requestID, idpEntityID, spEntityID, acsURL, username string,
) error {
	if response == nil || response.Assertion == nil {
		return errors.New("SAML response/assertion missing")
	}
	if response.Status.StatusCode.Value != "urn:oasis:names:tc:SAML:2.0:status:Success" {
		return fmt.Errorf("SAML status is %s", response.Status.StatusCode.Value)
	}
	if response.InResponseTo != requestID || response.Destination != acsURL {
		return errors.New("SAML response correlation or destination mismatch")
	}
	if response.Issuer == nil || response.Issuer.Text != idpEntityID {
		return errors.New("SAML response issuer mismatch")
	}
	assertion := response.Assertion
	if assertion.Issuer.Text != idpEntityID {
		return errors.New("SAML assertion issuer mismatch")
	}
	if assertion.Subject == nil || assertion.Subject.NameID == nil {
		return errors.New("SAML NameID missing")
	}
	if assertion.Subject.NameID.Format != "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" {
		return errors.New("unexpected SAML NameID format")
	}
	if !strings.Contains(assertion.Subject.NameID.Text, "@") {
		return errors.New("SAML NameID is not email-shaped")
	}
	if len(assertion.Subject.SubjectConfirmation) == 0 ||
		assertion.Subject.SubjectConfirmation[0].SubjectConfirmationData == nil {
		return errors.New("SAML SubjectConfirmationData missing")
	}
	confirmation := assertion.Subject.SubjectConfirmation[0].SubjectConfirmationData
	if confirmation.Recipient != acsURL || confirmation.InResponseTo != requestID {
		return errors.New("SAML SubjectConfirmationData mismatch")
	}
	if len(assertion.Conditions.AudienceRestriction) == 0 ||
		len(assertion.Conditions.AudienceRestriction[0].Audience) == 0 ||
		assertion.Conditions.AudienceRestriction[0].Audience[0] != spEntityID {
		return errors.New("SAML audience mismatch")
	}
	now := time.Now().UTC()
	notBefore, err := time.Parse(time.RFC3339, assertion.Conditions.NotBefore)
	if err != nil {
		return fmt.Errorf("invalid NotBefore: %w", err)
	}
	notAfter, err := time.Parse(time.RFC3339, assertion.Conditions.NotOnOrAfter)
	if err != nil {
		return fmt.Errorf("invalid NotOnOrAfter: %w", err)
	}
	if now.Add(2*time.Minute).Before(notBefore) || !now.Before(notAfter) {
		return errors.New("SAML assertion time conditions invalid")
	}
	attrs := map[string][]string{}
	for _, statement := range assertion.AttributeStatement {
		for _, attribute := range statement.Attribute {
			attrs[attribute.Name] = append(attrs[attribute.Name], attribute.AttributeValue...)
		}
	}
	if !contains(attrs["username"], username) {
		return errors.New("SAML local username attribute missing")
	}
	if len(attrs["Email"]) == 0 {
		return errors.New("SAML email attribute missing")
	}
	return nil
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func stringField(value map[string]any, key string) string {
	if v, ok := value[key].(string); ok {
		return v
	}
	return ""
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

var _ = xml.Header

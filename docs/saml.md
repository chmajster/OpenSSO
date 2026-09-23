# SAML 2.0 Identity Provider design

## Goal
Add SAML 2.0 Web Browser SSO to OpenSSO as a complete protocol slice. No SAML endpoint is exposed until metadata, request validation, signed responses/assertions, application registration, assignment checks and E2E verification are implemented together.

## Supported initial profile
- SAML 2.0 Web Browser SSO.
- SP-initiated SSO.
- HTTP-Redirect binding for AuthnRequest.
- HTTP-POST binding for SAMLResponse.
- IdP metadata.
- SP metadata import/registration.
- Signed SAML Responses and signed Assertions.
- NameID formats: persistent and emailAddress.
- Attribute mapping for email, display name, username and groups.
- Exact ACS URL validation against registered SP metadata.
- RelayState round-trip with bounded size.
- Integration with existing OpenSSO browser session, User Portal assignments, RBAC and audit.

Single Logout and artifact/PAOS bindings are intentionally outside this slice and will not be advertised in metadata until implemented.

## Security invariants
- Parse and validate XML using a maintained SAML/XML-signature stack; do not hand-roll XMLDSig.
- Reject unsigned AuthnRequests when the SP is configured to require request signatures.
- Validate XML signature before trusting Issuer, ACS, Destination or request ID fields that influence authorization/redirect behavior.
- Reject unknown SP EntityID and unregistered ACS URLs.
- Prevent XML Signature Wrapping by using a library path that validates references and signed-node identity.
- Bound request sizes, decompressed Redirect payload size, XML depth/library parser exposure and RelayState length.
- Enforce request ID uniqueness/replay window in PostgreSQL.
- Set AudienceRestriction to the registered SP EntityID.
- Set Recipient and SubjectConfirmationData Recipient to the validated ACS URL.
- Set InResponseTo to the validated AuthnRequest ID.
- Use short NotBefore/NotOnOrAfter windows and clock-skew tolerance.
- Sign with a dedicated SAML X.509 signing certificate/private key encrypted at rest with OPENSSO_MASTER_KEY.
- Never log raw SAML assertions, private keys or full signed protocol payloads.
- Audit success/failure without secrets.

## Data model
Protocol-specific state will be stored separately from existing OIDC tables:
- saml_service_providers
- saml_acs_endpoints
- saml_sp_certificates
- saml_attribute_mappings
- saml_authn_requests
- saml_signing_certificates

applications remains the shared catalog/assignment entity, with protocol expanded from oidc to oidc|saml.

## Endpoint plan
- GET /saml/metadata
- GET /saml/sso
- POST /saml/sso/consent or equivalent internal browser continuation only if required
- Administrative /api/v1/applications endpoints extended with SAML registration/integration details

## E2E
A real test SP must:
1. fetch IdP metadata;
2. send a Redirect-bound AuthnRequest;
3. authenticate through OpenSSO;
4. receive a POSTed SAMLResponse;
5. validate XML signature and certificate;
6. validate InResponseTo, Destination, Recipient, Audience, time conditions and attributes;
7. reject replay and invalid ACS/issuer/signature cases.

Merge remains blocked until this full flow passes on a fresh Docker Compose stack.

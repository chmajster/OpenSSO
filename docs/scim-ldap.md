# SCIM 2.0 and LDAP/Active Directory federation

## Scope

This stage adds two complete identity-integration surfaces without weakening the existing local, OIDC, SAML or MFA flows:

- SCIM 2.0 provisioning for Users and Groups.
- LDAP/Active Directory authentication and controlled identity synchronization.

## Security model

### SCIM

- Dedicated opaque bearer tokens are generated from cryptographically secure randomness.
- Only token hashes are stored.
- Tokens have explicit scopes and may be revoked.
- User and group writes are authorized independently.
- Protocol input is size-bounded and schema validated.
- Provisioning operations are audited without recording bearer tokens or passwords.
- Existing OpenSSO RBAC remains authoritative for administrative configuration.

### LDAP

- Bind credentials are encrypted at rest with the OpenSSO master key.
- TLS is required for credential-bearing remote LDAP connections; insecure LDAP is limited to explicitly configured development use.
- Search bases and filters are administrator controlled and validated.
- User-supplied identifiers are escaped before LDAP filter construction.
- Authentication does not persist the user's LDAP password.
- External identities are linked by stable provider identity rather than mutable display attributes.
- Account disablement and provider disablement fail closed.
- Local Super Admin recovery remains independent from an external directory.

## Data model

The implementation will add durable records for:

- SCIM bearer tokens and scopes;
- SCIM external identifiers;
- LDAP providers;
- LDAP identity links;
- synchronization state.

All schema changes use new numbered transactional migrations.

## SCIM surface

The supported protocol surface is intended to include:

- ServiceProviderConfig;
- ResourceTypes;
- Schemas;
- Users collection and resource operations;
- Groups collection and resource operations;
- filtering and pagination;
- PUT and PATCH semantics;
- stable SCIM error responses.

Unsupported optional SCIM features must not be advertised.

## LDAP/AD surface

Administration includes:

- provider create/update/delete;
- enable/disable;
- host/port and TLS mode;
- bind DN and encrypted bind secret;
- user/group search bases;
- configurable user lookup filter and attribute mapping;
- connection test;
- explicit synchronization;
- authentication through enabled providers;
- identity linking and audit history.

## Compatibility

Existing local authentication, MFA, OIDC and SAML flows must continue to pass their existing tests. Federated users remain subject to effective OpenSSO MFA policy after primary authentication.

## Verification

Completion requires backend tests, frontend lint/build, migration verification, protocol tests, negative authorization/input tests, LDAP integration tests, existing OIDC/MFA/SAML regression tests and live end-to-end verification.

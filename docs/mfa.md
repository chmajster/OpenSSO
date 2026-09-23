# Stage 3 MFA architecture

## Scope

Stage 3 implements:
- TOTP authenticators;
- single-use recovery codes;
- WebAuthn security keys;
- discoverable WebAuthn credentials (passkeys);
- MFA policies scoped globally, by group and by application;
- administrator MFA reset;
- self-service MFA management;
- MFA enforcement during local sign-in and OIDC authorization.

No SAML, SCIM, LDAP federation or upstream federation UI is added in this stage.

## Authentication state model

Password verification must not directly create a fully authenticated browser session when MFA is required.

The flow is split into:
1. primary authentication: username/email + password;
2. pre-authentication challenge state;
3. MFA verification using an enrolled allowed factor;
4. full browser session creation.

The pre-authentication state is:
- opaque and cryptographically random;
- stored server-side only as a hash;
- short-lived;
- single-use after successful MFA;
- bound to the user and originating login context;
- rate-limited through Redis.

OIDC authorization continues only after a full browser session exists.

## Factors

### TOTP

TOTP secrets are generated from cryptographic randomness and encrypted at rest with the existing OpenSSO master key. Enrollment is pending until the user proves possession with a valid OTP.

The backend accepts a narrow time window and rate-limits verification.

### Recovery codes

Recovery codes are:
- generated from cryptographic randomness;
- displayed only once at generation/regeneration;
- stored only as non-reversible hashes;
- single-use;
- invalidated when regenerated or when MFA is administratively reset.

Recovery-code use is audited without logging the code.

### WebAuthn and passkeys

WebAuthn protocol and cryptography are delegated to a maintained WebAuthn library.

Credential records store:
- credential ID;
- public key/credential data required for WebAuthn verification;
- sign counter and transport metadata;
- discoverable/passkey flag;
- display name;
- created/last-used timestamps.

Registration and authentication ceremonies use short-lived server-side challenge state and validate RP ID/origin against deployment configuration.

## MFA policy evaluation

Effective MFA requirement is the logical OR of:
- global requirement;
- any matching group policy;
- target application policy.

For ordinary portal login, global/group policies apply.
For OIDC authorization, application policy is added to the decision.

Policy evaluation happens in the backend before a full authenticated session can satisfy the requested operation.

## Administration

Administrators with MFA-management permission can:
- inspect user MFA status;
- reset all factors for a user;
- configure global policy;
- configure group policy;
- configure application policy.

Resetting MFA revokes active browser sessions for that user.

## Self-service

Users can:
- enroll/disable TOTP;
- register/remove WebAuthn credentials/passkeys;
- generate/regenerate recovery codes;
- inspect enrolled factors.

Destructive changes require an authenticated session and CSRF protection. Removing the final usable factor is rejected when the effective policy requires MFA.

## Audit

Stage 3 records:
- MFA_ENROLLMENT_STARTED
- MFA_ADDED
- MFA_REMOVED
- MFA_CHALLENGE_SUCCESS
- MFA_CHALLENGE_FAILED
- MFA_RECOVERY_USED
- MFA_RESET
- MFA_POLICY_CHANGED

No TOTP secrets, WebAuthn private material, recovery codes or challenge secrets are logged.

## Rate limiting

Redis-backed limits protect:
- MFA challenge verification;
- TOTP enrollment verification;
- WebAuthn authentication challenge completion;
- recovery-code verification.

## Horizontal scaling

All durable MFA enrollment state lives in PostgreSQL.
Short-lived challenge/pre-authentication state may be stored durably in PostgreSQL or in Redis when expiry semantics make Redis appropriate, but must remain shared between application instances.

ALTER TABLE sessions
  ADD COLUMN mfa_verified_at timestamptz;

ALTER TABLE security_policies
  ADD COLUMN mfa_required boolean NOT NULL DEFAULT false;

CREATE TABLE mfa_totp_credentials (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  encrypted_secret bytea NOT NULL,
  active boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  verified_at timestamptz,
  last_used_at timestamptz
);

CREATE TABLE mfa_recovery_codes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  used_at timestamptz,
  UNIQUE(user_id, code_hash)
);
CREATE INDEX mfa_recovery_codes_user_unused_idx
  ON mfa_recovery_codes(user_id)
  WHERE used_at IS NULL;

CREATE TABLE webauthn_users (
  user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  user_handle bytea NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE webauthn_credentials (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credential_id bytea NOT NULL UNIQUE,
  encrypted_credential bytea NOT NULL,
  display_name text NOT NULL,
  discoverable boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz
);
CREATE INDEX webauthn_credentials_user_idx ON webauthn_credentials(user_id);

CREATE TABLE group_mfa_policies (
  group_id uuid PRIMARY KEY REFERENCES groups(id) ON DELETE CASCADE,
  required boolean NOT NULL DEFAULT true,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE application_mfa_policies (
  application_id uuid PRIMARY KEY REFERENCES applications(id) ON DELETE CASCADE,
  required boolean NOT NULL DEFAULT true,
  updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO permissions(name,description) VALUES
('mfa.read','Read MFA enrollment and policy state'),
('mfa.write','Manage MFA enrollment and policies')
ON CONFLICT(name) DO NOTHING;

INSERT INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id
FROM roles r CROSS JOIN permissions p
WHERE r.name IN ('Super Admin','Admin','User Administrator','Security Administrator')
  AND p.name IN ('mfa.read','mfa.write')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id
FROM roles r CROSS JOIN permissions p
WHERE r.name='Read Only Administrator' AND p.name='mfa.read'
ON CONFLICT DO NOTHING;

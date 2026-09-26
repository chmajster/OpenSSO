CREATE TABLE scim_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  token_hash text NOT NULL UNIQUE,
  scopes text[] NOT NULL DEFAULT ARRAY['users.read','users.write','groups.read','groups.write']::text[],
  created_by uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  expires_at timestamptz,
  revoked_at timestamptz
);
CREATE INDEX scim_tokens_active_hash_idx ON scim_tokens(token_hash) WHERE revoked_at IS NULL;

CREATE TABLE scim_user_links (
  user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  external_id text UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE scim_group_links (
  group_id uuid PRIMARY KEY REFERENCES groups(id) ON DELETE CASCADE,
  external_id text UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE ldap_providers (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  enabled boolean NOT NULL DEFAULT true,
  host text NOT NULL,
  port integer NOT NULL CHECK(port BETWEEN 1 AND 65535),
  tls_mode text NOT NULL CHECK(tls_mode IN ('ldaps','starttls')),
  skip_tls_verify boolean NOT NULL DEFAULT false,
  bind_dn text NOT NULL DEFAULT '',
  encrypted_bind_password bytea,
  user_base_dn text NOT NULL,
  user_filter text NOT NULL DEFAULT '(&(objectClass=person)(sAMAccountName={username}))',
  user_id_attribute text NOT NULL DEFAULT 'objectGUID',
  username_attribute text NOT NULL DEFAULT 'sAMAccountName',
  email_attribute text NOT NULL DEFAULT 'mail',
  display_name_attribute text NOT NULL DEFAULT 'displayName',
  group_base_dn text NOT NULL DEFAULT '',
  group_filter text NOT NULL DEFAULT '(objectClass=group)',
  group_name_attribute text NOT NULL DEFAULT 'cn',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE ldap_identity_links (
  provider_id uuid NOT NULL REFERENCES ldap_providers(id) ON DELETE CASCADE,
  external_id text NOT NULL,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  distinguished_name text NOT NULL,
  last_synced_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(provider_id,external_id),
  UNIQUE(provider_id,user_id)
);
CREATE INDEX ldap_identity_links_user_idx ON ldap_identity_links(user_id);

INSERT INTO permissions(name,description) VALUES
('scim.read','Read SCIM configuration'),
('scim.write','Manage SCIM provisioning credentials'),
('ldap.read','Read LDAP federation configuration'),
('ldap.write','Manage LDAP federation configuration')
ON CONFLICT(name) DO NOTHING;

INSERT INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id FROM roles r CROSS JOIN permissions p WHERE r.name='Super Admin'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id FROM roles r JOIN permissions p ON p.name IN ('scim.read','scim.write','ldap.read','ldap.write')
WHERE r.name='Admin'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id FROM roles r JOIN permissions p ON p.name IN ('scim.read','ldap.read')
WHERE r.name='Read Only Administrator'
ON CONFLICT DO NOTHING;

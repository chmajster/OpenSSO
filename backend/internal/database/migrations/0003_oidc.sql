ALTER TABLE oauth_clients
  ADD COLUMN allowed_scopes text[] NOT NULL DEFAULT ARRAY['openid','profile','email','groups'],
  ADD COLUMN access_token_ttl_seconds integer NOT NULL DEFAULT 900 CHECK (access_token_ttl_seconds BETWEEN 60 AND 86400),
  ADD COLUMN id_token_ttl_seconds integer NOT NULL DEFAULT 900 CHECK (id_token_ttl_seconds BETWEEN 60 AND 86400),
  ADD COLUMN refresh_token_ttl_seconds integer NOT NULL DEFAULT 2592000 CHECK (refresh_token_ttl_seconds BETWEEN 300 AND 31536000);

CREATE TABLE oauth_post_logout_redirect_uris (
  application_id uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  redirect_uri text NOT NULL,
  PRIMARY KEY(application_id,redirect_uri)
);

CREATE TABLE oauth_consents (
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  application_id uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  granted_scopes text[] NOT NULL,
  granted_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(user_id,application_id)
);

CREATE TABLE oauth_authorization_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  request_token_hash text NOT NULL UNIQUE,
  application_id uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  redirect_uri text NOT NULL,
  state text NOT NULL,
  nonce text NOT NULL DEFAULT '',
  scope text NOT NULL,
  code_challenge text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz
);
CREATE INDEX oauth_authorization_requests_expiry_idx ON oauth_authorization_requests(expires_at);

CREATE TABLE authorization_codes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code_hash text NOT NULL UNIQUE,
  application_id uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  redirect_uri text NOT NULL,
  scope text NOT NULL,
  nonce text NOT NULL DEFAULT '',
  code_challenge text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz
);
CREATE INDEX authorization_codes_expiry_idx ON authorization_codes(expires_at);

CREATE TABLE refresh_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash text NOT NULL UNIQUE,
  family_id uuid NOT NULL,
  parent_id uuid REFERENCES refresh_tokens(id) ON DELETE SET NULL,
  application_id uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scope text NOT NULL,
  issued_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  revoked_at timestamptz
);
CREATE INDEX refresh_tokens_family_idx ON refresh_tokens(family_id);
CREATE INDEX refresh_tokens_expiry_idx ON refresh_tokens(expires_at);

CREATE TABLE oauth_access_tokens (
  jti uuid PRIMARY KEY,
  application_id uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  user_id uuid REFERENCES users(id) ON DELETE CASCADE,
  subject text NOT NULL,
  scope text NOT NULL,
  issued_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz
);
CREATE INDEX oauth_access_tokens_expiry_idx ON oauth_access_tokens(expires_at);

CREATE TABLE signing_keys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kid text NOT NULL UNIQUE,
  algorithm text NOT NULL CHECK(algorithm='RS256'),
  encrypted_private_key bytea NOT NULL,
  public_jwk jsonb NOT NULL,
  active boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz
);
CREATE UNIQUE INDEX signing_keys_single_active_idx ON signing_keys(active) WHERE active=true;

INSERT INTO permissions(name,description) VALUES
('signing_keys.read','Read signing key metadata'),
('signing_keys.rotate','Rotate OIDC signing keys')
ON CONFLICT(name) DO NOTHING;

INSERT INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id FROM roles r CROSS JOIN permissions p
WHERE r.name='Super Admin'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id FROM roles r JOIN permissions p ON p.name='signing_keys.read'
WHERE r.name='Read Only Administrator'
ON CONFLICT DO NOTHING;

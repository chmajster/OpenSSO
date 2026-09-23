ALTER TABLE applications
  DROP CONSTRAINT applications_protocol_check;

ALTER TABLE applications
  ADD CONSTRAINT applications_protocol_check
  CHECK (protocol IN ('oidc','saml'));

CREATE TABLE saml_service_providers (
  application_id uuid PRIMARY KEY REFERENCES applications(id) ON DELETE CASCADE,
  entity_id text NOT NULL UNIQUE,
  metadata_xml text NOT NULL,
  require_signed_authn_requests boolean NOT NULL DEFAULT false,
  name_id_source text NOT NULL DEFAULT 'email' CHECK(name_id_source IN ('email')),
  initiate_login_uri text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE saml_authn_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  request_key text NOT NULL UNIQUE,
  saml_request_id text NOT NULL UNIQUE,
  application_id uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  issuer text NOT NULL,
  destination text NOT NULL DEFAULT '',
  acs_url text NOT NULL,
  response_binding text NOT NULL,
  relay_state text NOT NULL DEFAULT '',
  user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  completed_at timestamptz,
  consumed_at timestamptz
);
CREATE INDEX saml_authn_requests_app_expiry_idx
  ON saml_authn_requests(application_id,expires_at);
CREATE INDEX saml_authn_requests_user_idx
  ON saml_authn_requests(user_id,created_at DESC);

CREATE TABLE saml_signing_certificates (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kid text NOT NULL UNIQUE,
  encrypted_private_key bytea NOT NULL,
  certificate_der bytea NOT NULL,
  not_before timestamptz NOT NULL,
  not_after timestamptz NOT NULL,
  active boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz
);
CREATE UNIQUE INDEX saml_signing_certificates_single_active_idx
  ON saml_signing_certificates(active) WHERE active=true;

INSERT INTO permissions(name,description) VALUES
('saml.read','Read SAML provider and certificate metadata'),
('saml.write','Manage SAML service providers'),
('saml.rotate','Rotate SAML signing certificate')
ON CONFLICT(name) DO NOTHING;

INSERT INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id
FROM roles r CROSS JOIN permissions p
WHERE r.name='Super Admin'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id
FROM roles r JOIN permissions p ON p.name IN ('saml.read','saml.write')
WHERE r.name IN ('Admin','Application Administrator')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id
FROM roles r JOIN permissions p ON p.name IN ('saml.read','saml.rotate')
WHERE r.name='Security Administrator'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id
FROM roles r JOIN permissions p ON p.name='saml.read'
WHERE r.name='Read Only Administrator'
ON CONFLICT DO NOTHING;

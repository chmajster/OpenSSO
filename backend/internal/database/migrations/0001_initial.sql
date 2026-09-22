CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE system_state (
  id smallint PRIMARY KEY DEFAULT 1 CHECK (id=1),
  initialized boolean NOT NULL DEFAULT false,
  initialized_at timestamptz
);
INSERT INTO system_state(id,initialized) VALUES(1,false) ON CONFLICT(id) DO NOTHING;

CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  username text NOT NULL UNIQUE,
  email text NOT NULL UNIQUE,
  display_name text NOT NULL DEFAULT '',
  active boolean NOT NULL DEFAULT true,
  failed_logins integer NOT NULL DEFAULT 0,
  locked_until timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE password_credentials (
  user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  password_hash text NOT NULL,
  changed_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE roles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  description text NOT NULL DEFAULT ''
);
CREATE TABLE permissions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  description text NOT NULL DEFAULT ''
);
CREATE TABLE role_permissions (
  role_id uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  permission_id uuid NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
  PRIMARY KEY(role_id,permission_id)
);
CREATE TABLE role_assignments (
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  PRIMARY KEY(user_id,role_id)
);
CREATE TABLE groups (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  description text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE group_memberships (
  group_id uuid NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(group_id,user_id)
);
CREATE TABLE applications (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  protocol text NOT NULL CHECK(protocol IN ('oidc')),
  enabled boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE oauth_clients (
  application_id uuid PRIMARY KEY REFERENCES applications(id) ON DELETE CASCADE,
  client_id text NOT NULL UNIQUE,
  client_secret_hash text,
  public_client boolean NOT NULL DEFAULT false,
  require_pkce boolean NOT NULL DEFAULT true
);
CREATE TABLE oauth_redirect_uris (
  application_id uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  redirect_uri text NOT NULL,
  PRIMARY KEY(application_id,redirect_uri)
);
CREATE TABLE sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash text NOT NULL UNIQUE,
  ip inet,
  user_agent text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz
);
CREATE INDEX sessions_user_idx ON sessions(user_id,expires_at) WHERE revoked_at IS NULL;
CREATE TABLE audit_events (
  id bigserial PRIMARY KEY,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  target_type text NOT NULL DEFAULT '',
  target_id text NOT NULL DEFAULT '',
  event text NOT NULL,
  result text NOT NULL,
  ip inet,
  user_agent text NOT NULL DEFAULT '',
  request_id text NOT NULL DEFAULT '',
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX audit_events_occurred_idx ON audit_events(occurred_at DESC);

INSERT INTO permissions(name,description) VALUES
('users.read','Read users'),('users.write','Manage users'),
('groups.read','Read groups'),('groups.write','Manage groups'),
('applications.read','Read applications'),('applications.write','Manage applications'),
('audit.read','Read audit events'),('rbac.write','Manage role assignments')
ON CONFLICT(name) DO NOTHING;

INSERT INTO roles(name,description) VALUES
('Super Admin','Unrestricted administrative access'),
('Read Only Administrator','Read-only administrative access'),
('User','Standard user access')
ON CONFLICT(name) DO NOTHING;

INSERT INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id FROM roles r CROSS JOIN permissions p WHERE r.name='Super Admin'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id FROM roles r JOIN permissions p ON p.name IN ('users.read','groups.read','applications.read','audit.read')
WHERE r.name='Read Only Administrator'
ON CONFLICT DO NOTHING;

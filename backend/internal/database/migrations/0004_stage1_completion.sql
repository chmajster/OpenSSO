ALTER TABLE oauth_clients
  ADD COLUMN initiate_login_uri text;

CREATE TABLE application_user_assignments (
  application_id uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(application_id,user_id)
);

CREATE TABLE application_group_assignments (
  application_id uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  group_id uuid NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(application_id,group_id)
);

INSERT INTO roles(name,description) VALUES
('Admin','Broad administrative access except Super Admin-only controls'),
('User Administrator','Manage users, groups and sessions'),
('Application Administrator','Manage applications and client integrations'),
('Security Administrator','Manage security policies, sessions, audit and signing keys')
ON CONFLICT(name) DO NOTHING;

INSERT INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id
FROM roles r CROSS JOIN permissions p
WHERE r.name='Admin' AND p.name <> 'signing_keys.rotate'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id
FROM roles r JOIN permissions p ON p.name IN (
  'users.read','users.write','groups.read','groups.write',
  'sessions.read','sessions.write'
)
WHERE r.name='User Administrator'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id
FROM roles r JOIN permissions p ON p.name IN (
  'applications.read','applications.write','users.read','groups.read'
)
WHERE r.name='Application Administrator'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id
FROM roles r JOIN permissions p ON p.name IN (
  'audit.read','policies.read','policies.write',
  'sessions.read','sessions.write',
  'signing_keys.read','signing_keys.rotate'
)
WHERE r.name='Security Administrator'
ON CONFLICT DO NOTHING;

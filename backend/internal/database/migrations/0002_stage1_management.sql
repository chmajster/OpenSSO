ALTER TABLE users
  ADD COLUMN must_change_password boolean NOT NULL DEFAULT false;

CREATE TABLE security_policies (
  id smallint PRIMARY KEY DEFAULT 1 CHECK (id=1),
  password_min_length integer NOT NULL DEFAULT 12 CHECK (password_min_length BETWEEN 12 AND 128),
  lockout_threshold integer NOT NULL DEFAULT 10 CHECK (lockout_threshold BETWEEN 3 AND 100),
  lockout_minutes integer NOT NULL DEFAULT 15 CHECK (lockout_minutes BETWEEN 1 AND 1440),
  session_ttl_minutes integer NOT NULL DEFAULT 720 CHECK (session_ttl_minutes BETWEEN 5 AND 10080),
  updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO security_policies(id) VALUES(1) ON CONFLICT(id) DO NOTHING;

INSERT INTO permissions(name,description) VALUES
('sessions.read','Read active sessions'),
('sessions.write','Revoke active sessions'),
('policies.read','Read security policies'),
('policies.write','Manage security policies')
ON CONFLICT(name) DO NOTHING;

INSERT INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id
FROM roles r CROSS JOIN permissions p
WHERE r.name='Super Admin'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id
FROM roles r JOIN permissions p ON p.name IN ('sessions.read','policies.read')
WHERE r.name='Read Only Administrator'
ON CONFLICT DO NOTHING;

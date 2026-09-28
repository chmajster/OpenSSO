CREATE TABLE login_ui_settings (
  id smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  enabled boolean NOT NULL DEFAULT false,
  brand_name varchar(100) NOT NULL DEFAULT 'OpenSSO',
  heading varchar(120) NOT NULL DEFAULT 'Sign in',
  subheading varchar(240) NOT NULL DEFAULT 'Use your OpenSSO account.',
  logo_url text NOT NULL DEFAULT '',
  background_image_url text NOT NULL DEFAULT '',
  background_color varchar(7) NOT NULL DEFAULT '#0b1020',
  card_color varchar(7) NOT NULL DEFAULT '#11192d',
  text_color varchar(7) NOT NULL DEFAULT '#e8edf5',
  muted_text_color varchar(7) NOT NULL DEFAULT '#9db0ca',
  primary_color varchar(7) NOT NULL DEFAULT '#5b7cfa',
  input_background_color varchar(7) NOT NULL DEFAULT '#0d1526',
  border_color varchar(7) NOT NULL DEFAULT '#223150',
  card_radius integer NOT NULL DEFAULT 16 CHECK (card_radius BETWEEN 0 AND 48),
  card_width integer NOT NULL DEFAULT 460 CHECK (card_width BETWEEN 320 AND 720),
  notice_text varchar(500) NOT NULL DEFAULT '',
  footer_text varchar(240) NOT NULL DEFAULT '',
  show_brand_name boolean NOT NULL DEFAULT true,
  show_footer boolean NOT NULL DEFAULT false,
  updated_at timestamptz NOT NULL DEFAULT now(),
  updated_by uuid REFERENCES users(id) ON DELETE SET NULL
);

INSERT INTO login_ui_settings(id) VALUES (1);

INSERT INTO permissions(name,description) VALUES
('branding.read','Read login UI and branding configuration'),
('branding.write','Manage login UI and branding configuration')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id
FROM roles r CROSS JOIN permissions p
WHERE r.name='Super Admin'
  AND p.name IN ('branding.read','branding.write')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id
FROM roles r JOIN permissions p ON p.name IN ('branding.read','branding.write')
WHERE r.name='Admin'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id
FROM roles r JOIN permissions p ON p.name='branding.read'
WHERE r.name='Read Only Administrator'
ON CONFLICT DO NOTHING;

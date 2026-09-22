ALTER TABLE security_policies
  ADD COLUMN password_require_upper boolean NOT NULL DEFAULT true,
  ADD COLUMN password_require_lower boolean NOT NULL DEFAULT true,
  ADD COLUMN password_require_digit boolean NOT NULL DEFAULT true,
  ADD COLUMN password_require_symbol boolean NOT NULL DEFAULT true;

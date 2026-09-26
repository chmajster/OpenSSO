ALTER TABLE ldap_providers
  ADD COLUMN sync_enabled boolean NOT NULL DEFAULT false,
  ADD COLUMN sync_interval_minutes integer NOT NULL DEFAULT 60 CHECK(sync_interval_minutes BETWEEN 5 AND 10080),
  ADD COLUMN last_sync_at timestamptz,
  ADD COLUMN last_sync_result text NOT NULL DEFAULT '',
  ADD COLUMN last_sync_error text NOT NULL DEFAULT '';

CREATE INDEX ldap_identity_links_provider_sync_idx
  ON ldap_identity_links(provider_id,last_synced_at);

-- +goose Up
------------------------------------------------------------------------------------------------
-- +goose statementbegin
CREATE OR REPLACE FUNCTION trigger_set_updated_at_column () RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = clock_timestamp();
    RETURN NEW;
END;
$$ LANGUAGE 'plpgsql';


-- +goose statementend
------------------------------------------------------------------------------------------------
CREATE TABLE permission (
  name VARCHAR(100) PRIMARY KEY NOT NULL CHECK (char_length(name) >= 1),
  created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT now() NOT NULL,
  deleted_at TIMESTAMPTZ
);


CREATE TABLE role (
  name VARCHAR(100) PRIMARY KEY NOT NULL CHECK (char_length(name) >= 1),
  created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT now() NOT NULL,
  deleted_at TIMESTAMPTZ
);


CREATE TABLE role_permission (
  role_name VARCHAR(100) NOT NULL REFERENCES role (name) ON DELETE CASCADE,
  permission_name VARCHAR(100) NOT NULL REFERENCES permission (name) ON DELETE CASCADE,
  created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT now() NOT NULL,
  PRIMARY KEY (role_name, permission_name)
);


CREATE TRIGGER update_permission_updated_at_column BEFORE
UPDATE ON permission FOR EACH ROW
EXECUTE PROCEDURE trigger_set_updated_at_column ();


CREATE TRIGGER update_role_updated_at_column BEFORE
UPDATE ON role FOR EACH ROW
EXECUTE PROCEDURE trigger_set_updated_at_column ();


CREATE TRIGGER update_role_permission_updated_at_column BEFORE
UPDATE ON role_permission FOR EACH ROW
EXECUTE PROCEDURE trigger_set_updated_at_column ();


------------------------------------------------------------------------------------------------
CREATE TABLE users (
  id SERIAL PRIMARY KEY NOT NULL,
  username VARCHAR(50) UNIQUE NOT NULL CHECK (char_length(username) >= 3),
  role_name VARCHAR(100) REFERENCES role (name),
  blocked_at TIMESTAMPTZ,
  blocked_until TIMESTAMPTZ,
  deleted_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT now() NOT NULL
);


CREATE TABLE user_info (
  id INT PRIMARY KEY NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  profile_image VARCHAR(2048),
  first_name VARCHAR(250) NOT NULL,
  last_name VARCHAR(250),
  updated_at TIMESTAMPTZ DEFAULT now() NOT NULL
);


CREATE VIEW user_with_info AS
SELECT
  u.id,
  u.username,
  u.role_name,
  u.blocked_at,
  u.blocked_until,
  u.deleted_at,
  u.created_at,
  u.updated_at AS user_updated_at,
  i.profile_image,
  i.first_name,
  i.last_name,
  i.updated_at AS info_updated_at
FROM
  users AS u
  JOIN user_info AS i ON u.id = i.id;


CREATE TRIGGER update_users_updated_at_column BEFORE
UPDATE ON users FOR EACH ROW
EXECUTE PROCEDURE trigger_set_updated_at_column ();


CREATE TRIGGER update_user_info_updated_at_column BEFORE
UPDATE ON user_info FOR EACH ROW
EXECUTE PROCEDURE trigger_set_updated_at_column ();


------------------------------------------------------------------------------------------------
CREATE TABLE login_identity (
  id SERIAL PRIMARY KEY NOT NULL,
  user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  identity_type TEXT NOT NULL,
  CONSTRAINT chk_login_identity_type CHECK (
    identity_type IN ('email', 'phone', 'oidc', 'guest')
  ),
  is_primary BOOLEAN DEFAULT FALSE,
  last_used_at TIMESTAMPTZ DEFAULT now() NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT now() NOT NULL,
  deleted_at TIMESTAMPTZ
);


CREATE TRIGGER update_login_identity_updated_at_column BEFORE
UPDATE ON login_identity FOR EACH ROW
EXECUTE PROCEDURE trigger_set_updated_at_column ();


CREATE VIEW active_login_identity AS
SELECT
  *
FROM
  login_identity
WHERE
  deleted_at IS NULL;


------------------------------------------------------------------------------------------------
CREATE TABLE session (
  id BIGSERIAL PRIMARY KEY NOT NULL,
  token VARCHAR(2048) UNIQUE NOT NULL CHECK (char_length(token) >= 50),
  -- the used ip address to create this session
  ip_address INET NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT now() NOT NULL,
  deleted_at TIMESTAMPTZ,
  purpose TEXT NOT NULL, -- login, mfa, etc....
  originated_from INTEGER NOT NULL REFERENCES login_identity (id) ON DELETE CASCADE
);


CREATE TABLE session_store (
  session TEXT NOT NULL,
  attr_key TEXT NOT NULL,
  attr_value TEXT,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT now() NOT NULL,
  PRIMARY KEY (session, attr_key)
);


CREATE TRIGGER update_session_updated_at_column BEFORE
UPDATE ON session FOR EACH ROW
EXECUTE PROCEDURE trigger_set_updated_at_column ();


CREATE TRIGGER update_session_store_updated_at_column BEFORE
UPDATE ON session_store FOR EACH ROW
EXECUTE PROCEDURE trigger_set_updated_at_column ();


------------------------------------------------------------------------------------------------
CREATE TABLE installation (
  id SERIAL PRIMARY KEY NOT NULL,
  installation_token VARCHAR(2048) UNIQUE NOT NULL,
  notification_token VARCHAR(2048),
  locale VARCHAR(16) NOT NULL CHECK (char_length(locale) >= 2),
  timezone_offset_in_minutes INTEGER NOT NULL CHECK (timezone_offset_in_minutes BETWEEN -720 AND 840),
  device_manufacturer VARCHAR(50) NULL,
  device_os VARCHAR(50) NOT NULL,
  client_type VARCHAR(50) NOT NULL,
  device_os_version VARCHAR(50) NULL,
  app_version VARCHAR(50) NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT now() NOT NULL,
  deleted_at TIMESTAMPTZ,
  attach_to BIGINT REFERENCES session (id) ON DELETE SET NULL,
  last_attach_to BIGINT REFERENCES session (id) ON DELETE SET NULL
);


CREATE TRIGGER update_installation_updated_at_column BEFORE
UPDATE ON installation FOR EACH ROW
EXECUTE PROCEDURE trigger_set_updated_at_column ();


CREATE VIEW not_deleted_installation AS
SELECT
  *
FROM
  installation
WHERE
  deleted_at IS NULL;


------------------------------------------------------------------------------------------------
ALTER TABLE session
ADD used_installation INTEGER NOT NULL REFERENCES installation (id);


CREATE VIEW active_session AS
SELECT
  *
FROM
  session
WHERE
  deleted_at IS NULL
  AND expires_at > NOW();


------------------------------------------------------------------------------------------------
CREATE TABLE password_login_identity (
  id SERIAL PRIMARY KEY NOT NULL,
  login_identity_id INTEGER NOT NULL UNIQUE REFERENCES login_identity (id) ON DELETE CASCADE,
  email VARCHAR(255),
  phone VARCHAR(16), -- E.164 format
  hashed_pass VARCHAR(128) NOT NULL,
  pass_salt VARCHAR(64) NOT NULL,
  verified_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  deleted_at TIMESTAMPTZ,
  -- Enforce only one of phone/email
  CHECK (
    (
      email IS NOT NULL
      AND phone IS NULL
    )
    OR (
      phone IS NOT NULL
      AND email IS NULL
    )
  ),
  -- Enforce E.164 format
  CHECK (
    phone IS NULL
    OR phone ~ '^\+[1-9]\d{1,14}$'
  )
);


-- Partial unique indexes
CREATE UNIQUE INDEX unique_email_login ON password_login_identity (email)
WHERE
  email IS NOT NULL;


CREATE UNIQUE INDEX unique_phone_login ON password_login_identity (phone)
WHERE
  phone IS NOT NULL;


CREATE TRIGGER update_password_login_identity_updated_at_column BEFORE
UPDATE ON password_login_identity FOR EACH ROW
EXECUTE PROCEDURE trigger_set_updated_at_column ();


CREATE VIEW active_password_login_identity AS
SELECT
  *
FROM
  password_login_identity
WHERE
  verified_at IS NOT NULL
  AND deleted_at IS NULL;


------------------------------------------------------------------------------------------------
CREATE TABLE guest_login_identity (
  id SERIAL PRIMARY KEY NOT NULL,
  login_identity_id INTEGER NOT NULL UNIQUE REFERENCES login_identity (id) ON DELETE CASCADE,
  device_id TEXT NOT NULL UNIQUE CHECK (
    char_length(device_id) > 0
    AND char_length(device_id) <= 2048
  ),
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  deleted_at TIMESTAMPTZ
);


CREATE TRIGGER update_guest_login_identity_updated_at_column BEFORE
UPDATE ON guest_login_identity FOR EACH ROW
EXECUTE PROCEDURE trigger_set_updated_at_column ();


CREATE VIEW active_guest_login_identity AS
SELECT
  *
FROM
  guest_login_identity
WHERE
  deleted_at IS NULL;


------------------------------------------------------------------------------------------------
CREATE TABLE oauth_provider (
  name VARCHAR(50) PRIMARY KEY NOT NULL, -- e.g., "google", "github"
  is_oidc_capable BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMPTZ
);


CREATE TRIGGER update_oauth_provider_updated_at_column BEFORE
UPDATE ON oauth_provider FOR EACH ROW
EXECUTE PROCEDURE trigger_set_updated_at_column ();


CREATE VIEW active_oauth_provider AS
SELECT
  *
FROM
  oauth_provider
WHERE
  deleted_at IS NULL;


------------------------------------------------------------------------------------------------
CREATE TABLE oauth_connection (
  id SERIAL PRIMARY KEY NOT NULL,
  provider_name TEXT NOT NULL REFERENCES oauth_provider (name) ON DELETE CASCADE,
  scopes TEXT[] NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMPTZ,
  UNIQUE (provider_name, scopes)
);


-- +goose statementbegin
CREATE OR REPLACE FUNCTION oauth_connection_sort_and_dedupe_scopes_array_fn () RETURNS TRIGGER AS $$
BEGIN
  NEW.scopes := (
    SELECT array_agg(DISTINCT s ORDER BY s)
    FROM unnest(NEW.scopes) s
  );
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;


-- +goose statementend
CREATE TRIGGER oauth_connection_sort_and_dedupe_scopes_trigger BEFORE INSERT
OR
UPDATE ON oauth_connection FOR EACH ROW
EXECUTE FUNCTION oauth_connection_sort_and_dedupe_scopes_array_fn ();


CREATE TRIGGER update_oauth_connection_updated_at_column BEFORE
UPDATE ON oauth_connection FOR EACH ROW
EXECUTE PROCEDURE trigger_set_updated_at_column ();


CREATE VIEW active_oauth_connection AS
SELECT
  *
FROM
  oauth_connection
WHERE
  deleted_at IS NULL;


------------------------------------------------------------------------------------------------
CREATE TABLE oauth_integration (
  id SERIAL PRIMARY KEY NOT NULL,
  oauth_connection_id INTEGER NOT NULL REFERENCES oauth_connection (id) ON DELETE CASCADE,
  integration_type TEXT NOT NULL,
  CONSTRAINT chk_oauth_integration_type CHECK (integration_type IN ('user', 'system')),
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  deleted_at TIMESTAMPTZ
);


CREATE TRIGGER update_oauth_integration_updated_at_column BEFORE
UPDATE ON oauth_integration FOR EACH ROW
EXECUTE PROCEDURE trigger_set_updated_at_column ();


CREATE VIEW active_oauth_integration AS
SELECT
  *
FROM
  oauth_integration
WHERE
  deleted_at IS NULL;


------------------------------------------------------------------------------------------------
CREATE TABLE oauth_token (
  id SERIAL PRIMARY KEY NOT NULL,
  oauth_integration_id INTEGER NOT NULL UNIQUE REFERENCES oauth_integration (id) ON DELETE CASCADE,
  access_token VARCHAR(2048), -- encrypted
  refresh_token VARCHAR(2048), -- encrypted
  token_type VARCHAR(50) NOT NULL DEFAULT 'Bearer',
  expires_at TIMESTAMP,
  issued_at TIMESTAMP NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  deleted_at TIMESTAMPTZ
);


CREATE TRIGGER update_oauth_token_updated_at_column BEFORE
UPDATE ON oauth_token FOR EACH ROW
EXECUTE PROCEDURE trigger_set_updated_at_column ();


CREATE VIEW active_oauth_token AS
SELECT
  *
FROM
  oauth_token
WHERE
  deleted_at IS NULL;


------------------------------------------------------------------------------------------------
CREATE TABLE user_integration (
  id SERIAL PRIMARY KEY NOT NULL,
  oauth_integration_id INTEGER NOT NULL UNIQUE REFERENCES oauth_integration (id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users (id),
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  deleted_at TIMESTAMPTZ
);


CREATE TRIGGER update_user_integration_updated_at_column BEFORE
UPDATE ON user_integration FOR EACH ROW
EXECUTE PROCEDURE trigger_set_updated_at_column ();


CREATE VIEW active_user_integration AS
SELECT
  *
FROM
  user_integration
WHERE
  deleted_at IS NULL;


------------------------------------------------------------------------------------------------
CREATE TABLE oidc_data (
  id SERIAL PRIMARY KEY NOT NULL,
  provider_name TEXT NOT NULL REFERENCES oauth_provider (name) ON DELETE CASCADE,
  sub TEXT NOT NULL,
  email VARCHAR(255),
  iss TEXT NOT NULL,
  aud TEXT NOT NULL,
  given_name VARCHAR(250) DEFAULT '',
  family_name VARCHAR(250) DEFAULT '',
  name VARCHAR(250) DEFAULT '',
  picture TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  deleted_at TIMESTAMPTZ
);


-- Partial unique indexes
CREATE UNIQUE INDEX unique_email_oidc ON oidc_data (email)
WHERE
  email IS NOT NULL;


CREATE INDEX index_sub_oidc ON oidc_data (sub);


CREATE TRIGGER update_oidc_data_updated_at_column BEFORE
UPDATE ON oidc_data FOR EACH ROW
EXECUTE PROCEDURE trigger_set_updated_at_column ();


CREATE VIEW active_oidc_data AS
SELECT
  *
FROM
  oidc_data
WHERE
  deleted_at IS NULL;


------------------------------------------------------------------------------------------------
CREATE TABLE oidc_login_identity (
  id SERIAL PRIMARY KEY NOT NULL,
  login_identity_id INTEGER NOT NULL UNIQUE REFERENCES login_identity (id) ON DELETE CASCADE,
  oidc_data_id INTEGER NOT NULL UNIQUE REFERENCES oidc_data (id),
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  deleted_at TIMESTAMPTZ
);


CREATE TRIGGER update_oidc_login_identity_updated_at_column BEFORE
UPDATE ON oidc_login_identity FOR EACH ROW
EXECUTE PROCEDURE trigger_set_updated_at_column ();


CREATE VIEW active_oidc_login_identity AS
SELECT
  *
FROM
  oidc_login_identity
WHERE
  deleted_at IS NULL;


------------------------------------------------------------------------------------------------
CREATE TABLE system_integration (
  id SERIAL PRIMARY KEY NOT NULL,
  oauth_integration_id INTEGER NOT NULL UNIQUE REFERENCES oauth_integration (id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  deleted_at TIMESTAMPTZ
);


CREATE TRIGGER update_system_integration_updated_at_column BEFORE
UPDATE ON system_integration FOR EACH ROW
EXECUTE PROCEDURE trigger_set_updated_at_column ();


CREATE VIEW active_system_integration AS
SELECT
  *
FROM
  system_integration
WHERE
  deleted_at IS NULL;


------------------------------------------------------------------------------------------------
CREATE TABLE otp_challenge (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  otp_hash TEXT NOT NULL,
  channel TEXT NOT NULL, -- 'sms' or 'email'
  attempts INT DEFAULT 0,
  purpose TEXT NOT NULL, -- create account, reset password, etc....
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL
);


CREATE TRIGGER update_otp_challenge_updated_at_column BEFORE
UPDATE ON otp_challenge FOR EACH ROW
EXECUTE PROCEDURE trigger_set_updated_at_column ();


------------------------------------------------------------------------------------------------
-- mfa_methods: each row = an enrolled factor
CREATE TABLE mfa_method (
  id SERIAL PRIMARY KEY NOT NULL,
  status text NOT NULL,
  CONSTRAINT chk_mfa_methods_status CHECK (
    status IN ('pending', 'verified', 'disabled', 'revoked')
  ),
  method_type TEXT NOT NULL,
  CONSTRAINT chk_mfa_methods_method_type CHECK (
    method_type IN ('email', 'phone', 'totp', 'webauthn')
  ),
  user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  label TEXT NOT NULL DEFAULT '', -- e.g. "Phone 1", "YubiKey", "home phone"
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);


CREATE INDEX index_mfa_method__user_id ON mfa_method (user_id);


CREATE TABLE mfa_method_type_email (
  id INTEGER PRIMARY KEY NOT NULL REFERENCES mfa_method (id) ON DELETE CASCADE,
  ownership_verification UUID REFERENCES otp_challenge (id) ON DELETE SET NULL,
  email VARCHAR(255) NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);


CREATE INDEX index_mfa_method_type_email__email ON mfa_method_type_email (email);


CREATE TABLE mfa_method_type_phone (
  id INTEGER PRIMARY KEY NOT NULL REFERENCES mfa_method (id) ON DELETE CASCADE,
  ownership_verification UUID NULL REFERENCES otp_challenge (id) ON DELETE SET NULL,
  phone VARCHAR(16) NOT NULL, -- E.164 format
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);


CREATE INDEX index_mfa_method_type_phone__phone ON mfa_method_type_phone (phone);


CREATE TABLE mfa_method_type_totp (
  id INTEGER PRIMARY KEY NOT NULL REFERENCES mfa_method (id) ON DELETE CASCADE,
  secret_key TEXT NOT NULL, -- encrypted
  algorithm TEXT NOT NULL DEFAULT 'SHA-1',
  CONSTRAINT chk_mfa_method_type_totp_algorithm CHECK (
    algorithm IN ('SHA-1', 'SHA-256', 'SHA-512', 'MD5')
  ),
  digits INTEGER NOT NULL DEFAULT 6,
  period INTEGER NOT NULL DEFAULT 30, --seconds
  issuer TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);


CREATE TABLE mfa_session (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  purpose TEXT NOT NULL, -- login, change password, delete account, etc....
  expires_at timestamptz NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);


CREATE TABLE pending_mfa_session (
  mfa_session UUID NOT NULL REFERENCES mfa_session (id) ON DELETE CASCADE,
  mfa_method INTEGER NOT NULL REFERENCES mfa_method (id) ON DELETE CASCADE,
  otp_challenge UUID REFERENCES otp_challenge (id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  PRIMARY KEY (mfa_session, mfa_method)
);


CREATE TABLE backup_codes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  code_hash text NOT NULL,
  used boolean DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);


CREATE INDEX idx__backup_codes__user_id ON backup_codes (user_id);


CREATE TABLE mfa_remembered_devices (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  device_fingerprint text NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  expires_at timestamptz,
  last_used TIMESTAMPTZ
);


CREATE INDEX idx__mfa_remembered_devices__user_id__device_fingerprint ON mfa_remembered_devices (user_id, device_fingerprint);


CREATE TRIGGER update_mfa_remembered_devices_updated_at_column BEFORE
UPDATE ON mfa_remembered_devices FOR EACH ROW
EXECUTE PROCEDURE trigger_set_updated_at_column ();


CREATE TRIGGER update_mfa_method_updated_at_column BEFORE
UPDATE ON mfa_method FOR EACH ROW
EXECUTE PROCEDURE trigger_set_updated_at_column ();


CREATE TRIGGER update_mfa_method_type_totp_updated_at_column BEFORE
UPDATE ON mfa_method_type_totp FOR EACH ROW
EXECUTE PROCEDURE trigger_set_updated_at_column ();


CREATE TRIGGER update_mfa_method_type_email_updated_at_column BEFORE
UPDATE ON mfa_method_type_email FOR EACH ROW
EXECUTE PROCEDURE trigger_set_updated_at_column ();


CREATE TRIGGER update_mfa_method_type_phone_updated_at_column BEFORE
UPDATE ON mfa_method_type_phone FOR EACH ROW
EXECUTE PROCEDURE trigger_set_updated_at_column ();


CREATE TRIGGER update_backup_codes_updated_at_column BEFORE
UPDATE ON backup_codes FOR EACH ROW
EXECUTE PROCEDURE trigger_set_updated_at_column ();


CREATE TRIGGER update_mfa_session_updated_at_column BEFORE
UPDATE ON mfa_session FOR EACH ROW
EXECUTE PROCEDURE trigger_set_updated_at_column ();


CREATE TRIGGER update_pending_mfa_session_updated_at_column BEFORE
UPDATE ON pending_mfa_session FOR EACH ROW
EXECUTE PROCEDURE trigger_set_updated_at_column ();


------------------------------------------------------------------------------------------------
CREATE TABLE settings (
  label VARCHAR(100) PRIMARY KEY NOT NULL CHECK (char_length(label) >= 1),
  value TEXT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);


CREATE TRIGGER update_settings_updated_at_column BEFORE
UPDATE ON settings FOR EACH ROW
EXECUTE PROCEDURE trigger_set_updated_at_column ();


------------------------------------------------------------------------------------------------
CREATE TABLE seeder_version (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  version INTEGER UNIQUE NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


------------------------------------------------------------------------------------------------
-- +goose Down
------------------------------------------------------------------------------------------------
DROP TABLE seeder_version;


------------------------------------------------------------------------------------------------
DROP TABLE settings;


------------------------------------------------------------------------------------------------
DROP TABLE pending_mfa_session;


DROP TABLE mfa_session;


DROP TABLE mfa_method_type_email;


DROP TABLE mfa_method_type_phone;


DROP TABLE mfa_method_type_totp;


DROP TABLE mfa_method;


DROP TABLE backup_codes;


DROP TABLE mfa_remembered_devices;


------------------------------------------------------------------------------------------------
DROP TABLE otp_challenge;


------------------------------------------------------------------------------------------------
DROP VIEW active_system_integration;


DROP TABLE system_integration;


------------------------------------------------------------------------------------------------
DROP VIEW active_oidc_login_identity;


DROP TABLE oidc_login_identity;


------------------------------------------------------------------------------------------------
DROP VIEW active_oidc_data;


DROP TABLE oidc_data;


------------------------------------------------------------------------------------------------
DROP VIEW active_user_integration;


DROP TABLE user_integration;


------------------------------------------------------------------------------------------------
DROP VIEW active_oauth_token;


DROP TABLE oauth_token;


------------------------------------------------------------------------------------------------
DROP VIEW active_oauth_integration;


DROP TABLE oauth_integration;


------------------------------------------------------------------------------------------------
DROP VIEW active_oauth_connection;


DROP TABLE oauth_connection;


DROP FUNCTION oauth_connection_sort_and_dedupe_scopes_array_fn;


------------------------------------------------------------------------------------------------
DROP VIEW active_oauth_provider;


DROP TABLE oauth_provider;


------------------------------------------------------------------------------------------------
DROP VIEW active_guest_login_identity;


DROP TABLE guest_login_identity;


------------------------------------------------------------------------------------------------
DROP VIEW active_password_login_identity;


DROP TABLE password_login_identity;


------------------------------------------------------------------------------------------------
DROP VIEW active_session;


ALTER TABLE session
DROP COLUMN used_installation;


------------------------------------------------------------------------------------------------
DROP VIEW not_deleted_installation;


DROP TABLE installation;


------------------------------------------------------------------------------------------------
DROP TABLE session_store;


DROP TABLE session;


------------------------------------------------------------------------------------------------
DROP VIEW active_login_identity;


DROP TABLE login_identity;


------------------------------------------------------------------------------------------------
DROP VIEW user_with_info;


DROP TABLE user_info;


DROP TABLE users;


------------------------------------------------------------------------------------------------
DROP TABLE role_permission;


DROP TABLE role;


DROP TABLE permission;


------------------------------------------------------------------------------------------------
DROP FUNCTION trigger_set_updated_at_column;


------------------------------------------------------------------------------------------------

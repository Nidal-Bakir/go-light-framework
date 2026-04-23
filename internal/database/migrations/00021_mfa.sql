-- +goose Up
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
  secret_key TEXT NOT NULL,
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
  used boolean DEFAULT false,
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

-- +goose Down
DROP TABLE pending_mfa_session;

DROP TABLE mfa_session;

DROP TABLE mfa_method_type_email;

DROP TABLE mfa_method_type_phone;

DROP TABLE mfa_method_type_totp;

DROP TABLE mfa_method;

DROP TABLE backup_codes;

DROP TABLE mfa_remembered_devices;

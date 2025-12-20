-- -- +goose Up

-- -- mfa_methods: each row = an enrolled factor
-- CREATE TABLE mfa_method (
--     id SERIAL PRIMARY KEY NOT NULL,
--     status text NOT NULL,
--     CONSTRAINT chk_mfa_methods_status
--         CHECK (status IN ('pending', 'verified', 'disabled', 'revoked')),
--     method_type TEXT NOT NULL,
--     CONSTRAINT chk_mfa_methods_method_type
--         CHECK (method_type IN ('email', 'phone', 'totp', 'hotp', 'webauthn')),
--     user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
--     label TEXT NOT NULL, -- e.g. "Phone 1", "YubiKey", "home phone"
--     created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
--     updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
-- );

-- CREATE TABLE mfa_method_type_email (
--     id INTEGER PRIMARY KEY NOT NULL REFERENCES mfa_methods(id) ON DELETE CASCADE,
--     email VARCHAR(255) NOT NULL,
--     created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
--     updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
-- );

-- CREATE TABLE mfa_method_type_phone (
--     id INTEGER PRIMARY KEY NOT NULL REFERENCES mfa_methods(id) ON DELETE CASCADE,
--     phone VARCHAR(16) NOT NULL, -- E.164 format
--     created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
--     updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
-- );

-- CREATE TABLE mfa_method_type_totp (
--     id INTEGER PRIMARY KEY NOT NULL REFERENCES mfa_methods(id) ON DELETE CASCADE,
--     secret_key TEXT NOT NULL,
--     algorithm TEXT NOT NULL DEFAULT 'SHA-1',
--     CONSTRAINT chk_mfa_method_type_totp_algorithm
--         CHECK (algorithm IN ('SHA-1', 'SHA-256', 'SHA-512')),
--     digits INTEGER NOT NULL DEFAULT 6, -- Typically between 6 and 10, 6 is the recommended on
--     issuer TEXT NOT NULL,
--     time_step INTEGER NOT NULL,
--     initial_time INTEGER NOT NULL DEFAULT 0, -- Default: 0 (the Unix epoch, January 1, 1970, 00:00:00 UTC).
--     created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
--     updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
-- );

-- CREATE TABLE mfa_method_type_hotp (
--     id INTEGER PRIMARY KEY NOT NULL REFERENCES mfa_methods(id) ON DELETE CASCADE,
--     secret_key TEXT NOT NULL,
--     algorithm TEXT NOT NULL DEFAULT 'SHA-1', -- SHA-1, SHA-256 or SHA-512
--     CONSTRAINT chk_mfa_method_type_totp_algorithm
--         CHECK (algorithm IN ('SHA-1', 'SHA-256', 'SHA-512')),
--     digits INTEGER NOT NULL DEFAULT 6, -- Typically between 6 and 10, 6 is the recommended on
--     issuer TEXT NOT NULL,
--     counter INTEGER NOT NULL,
--     created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
--     updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
-- );


-- CREATE TABLE pending_mfa_session (
--   id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--   user_id UUID REFERENCES users(id) ON DELETE CASCADE,
--   created_at TIMESTAMPTZ DEFAULT now(),
--   expires_at TIMESTAMPTZ NOT NULL,
--   purpose text NOT NULL, -- 'login' or 'stepup:change_email'
--   client_nonce text, -- optional client-sent identifier to prevent replay
--   attempts integer DEFAULT 0
-- );

-- CREATE TABLE backup_codes (
--   id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--   user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
--   code_hash text NOT NULL,
--   used boolean DEFAULT false,
--   created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
--   updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
-- );

-- CREATE TABLE mfa_policies (
--   user_id INTEGER PRIMARY KEY NOT NULL REFERENCES users(id) ON DELETE CASCADE,
--   enforce boolean NOT NULL DEFAULT FALSE,
--   enforced_mfa_method INTEGER NULL REFERENCES mfa_methods(id)
--   created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
--   updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
-- );

-- CREATE TABLE mfa_remembered_devices (
--   id SERIAL PRIMARY KEY NOT NULL,
--   user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
--   device_fingerprint text NOT NULL,
--   created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
--   updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
--   expires_at timestamptz,
--   last_used TIMESTAMPTZ,
--   revoked boolean DEFAULT false
-- );

-- CREATE TRIGGER update_mfa_remembered_devices_updated_at_column BEFORE
-- UPDATE ON mfa_remembered_devices FOR EACH ROW EXECUTE PROCEDURE trigger_set_updated_at_column();
-- CREATE TRIGGER update_mfa_methods_updated_at_column BEFORE
-- UPDATE ON mfa_methods FOR EACH ROW EXECUTE PROCEDURE trigger_set_updated_at_column ();
-- CREATE TRIGGER update_backup_codes_devices_updated_at_column BEFORE
-- UPDATE ON backup_codes FOR EACH ROW EXECUTE PROCEDURE trigger_set_updated_at_column();
-- CREATE TRIGGER update_mfa_policies_updated_at_column BEFORE
-- UPDATE ON mfa_policies FOR EACH ROW EXECUTE PROCEDURE trigger_set_updated_at_column();

-- CREATE INDEX idx__mfa_remembered_devices__user_id__device_fingerprint ON mfa_remembered_devices (user_id, device_fingerprint);
-- CREATE INDEX idx__backup_codes__user_id ON backup_codes (user_id);

-- -- +goose Down
-- DROP TABLE mfa_methods;
-- DROP TABLE backup_codes;
-- DROP TABLE mfa_remembered_devices;
-- DROP TABLE mfa_policies;

-- +goose Up
CREATE TABLE session (
  id BIGSERIAL PRIMARY KEY NOT NULL,
  token VARCHAR(2048) UNIQUE NOT NULL CHECK (char_length(token) >= 50),
  -- the used ip address to create this session
  ip_address INET NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  purpose TEXT NOT NULL, -- login, mfa, etc....
  originated_from INTEGER NOT NULL REFERENCES login_identity (id) ON DELETE CASCADE
);

CREATE TABLE session_store (
  session TEXT NOT NULL,
  attr_key TEXT NOT NULL,
  attr_value TEXT,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  PRIMARY KEY (session, attr_key)
);

CREATE TRIGGER update_session_updated_at_column BEFORE
UPDATE ON session FOR EACH ROW
EXECUTE PROCEDURE trigger_set_updated_at_column ();

CREATE TRIGGER update_session_store_updated_at_column BEFORE
UPDATE ON session_store FOR EACH ROW
EXECUTE PROCEDURE trigger_set_updated_at_column ();

-- +goose Down
DROP TABLE session_store;

DROP TABLE session;

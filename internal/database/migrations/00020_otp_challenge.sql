-- +goose Up
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
UPDATE ON otp_challenge FOR EACH ROW EXECUTE PROCEDURE trigger_set_updated_at_column();

-- +goose Down
DROP TABLE otp_challenge;

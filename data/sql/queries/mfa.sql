-- name: MfaCreateTypeEmail :one
WITH
  new_mfa_method AS (
    INSERT INTO
      mfa_method (status, method_type, user_id, label)
    VALUES
      ('pending', 'email', @user_id::INT, @label::TEXT)
    RETURNING
      id
  )
INSERT INTO
  mfa_method_type_email (id, ownership_verification, email)
VALUES
  (
    (
      SELECT
        id
      FROM
        new_mfa_method
    ),
    @ownership_verification::UUID,
    @email::TEXT
  )
RETURNING
  id;

-- name: MfaGetEmailMfaForUser :one
SELECT
  m.id,
  m.status,
  m.method_type,
  m.user_id,
  m.label,
  m.created_at AS method_created_at,
  m.updated_at AS method_updated_at,
  e.ownership_verification,
  e.email,
  e.created_at AS email_created_at,
  e.updated_at AS email_updated_at
FROM
  mfa_method AS m
  JOIN mfa_method_type_email AS e ON m.id = e.id
WHERE
  m.user_id = @user_id::INT
  AND e.email = @email::TEXT
LIMIT
  1;

-- name: MfaGetOwnershipVerificationId :one
SELECT
  m.method_type,
  e.ownership_verification AS email_ownership_verification,
  p.ownership_verification AS phone_ownership_verification
FROM
  mfa_method AS m
  LEFT JOIN mfa_method_type_email AS e ON m.id = e.id
  LEFT JOIN mfa_method_type_phone AS p ON m.id = p.id
WHERE
  m.user_id = @user_id::INT
  AND m.id = @mfa_id::INT
  AND m.status = 'pending'
LIMIT
  1;

-- name: MfaUpdateOwnershipVerificationForMfaMethodTypeEmail :exec
UPDATE mfa_method_type_email
SET
  ownership_verification = @ownership_verification::UUID
WHERE
  id = @id::INT;

-- name: MfaCreateTypePhone :one
WITH
  new_mfa_method AS (
    INSERT INTO
      mfa_method (status, method_type, user_id, label)
    VALUES
      ('pending', 'phone', @user_id::INT, @label::TEXT)
    RETURNING
      id
  )
INSERT INTO
  mfa_method_type_phone (id, ownership_verification, phone)
VALUES
  (
    (
      SELECT
        id
      FROM
        new_mfa_method
    ),
    @ownership_verification::UUID,
    @phone::TEXT
  )
RETURNING
  id;

-- name: MfaGetPhoneMfaForUser :one
SELECT
  m.id,
  m.status,
  m.method_type,
  m.user_id,
  m.label,
  m.created_at AS method_created_at,
  m.updated_at AS method_updated_at,
  p.ownership_verification,
  p.phone,
  p.created_at AS email_created_at,
  p.updated_at AS email_updated_at
FROM
  mfa_method AS m
  JOIN mfa_method_type_phone AS p ON m.id = p.id
WHERE
  m.user_id = @user_id::INT
  AND p.phone = @phone::TEXT
LIMIT
  1;

-- name: MfaUpdateOwnershipVerificationForMfaMethodTypePhone :exec
UPDATE mfa_method_type_phone
SET
  ownership_verification = @ownership_verification::UUID
WHERE
  id = @id::INT;

-- name: MfaCountVerifiedMfaForUser :one
SELECT
  COUNT(*)
FROM
  mfa_method
WHERE
  user_id = @user_id
  AND status = 'verified';

-- name: MfaChangeMfaMethodStatus :exec
UPDATE mfa_method
SET
  status = @new_status::TEXT
WHERE
  id = @id::INT;

-- name: MfaGetMethod :one
SELECT
  m.id AS id,
  m.status AS status,
  m.method_type AS method_type,
  m.user_id AS user_id,
  m.label AS label,
  e.email AS method_email_email,
  p.phone AS method_phone_phone,
  t.algorithm AS method_totp_algorithm
FROM
  mfa_method AS m
  LEFT JOIN mfa_method_type_email AS e ON m.id = e.id
  LEFT JOIN mfa_method_type_phone AS p ON m.id = p.id
  LEFT JOIN mfa_method_type_totp AS t ON m.id = t.id
WHERE
  m.user_id = @user_id::INT
  AND m.id = @id::INT
  AND (
    sqlc.narg(status)::TEXT IS NULL
    OR m.status = @status::TEXT
  )
LIMIT
  1;
  
-- name: MfaGetTotpMethod :one
SELECT
  m.id AS id,
  m.status AS status,
  m.method_type AS method_type,
  m.user_id AS user_id,
  m.label AS label,
  t.secret_key AS method_totp_secret_key,
  t.algorithm AS method_totp_algorithm,
  t.digits AS method_totp_digits,
  t.period AS method_totp_period,
  t.issuer AS method_totp_issuer
FROM
  mfa_method AS m
  LEFT JOIN mfa_method_type_totp AS t ON m.id = t.id
WHERE
  m.user_id = @user_id::INT
  AND m.id = @id::INT
  AND m.method_type = 'totp'
  AND (
    sqlc.narg(status)::TEXT IS NULL
    OR m.status = @status::TEXT
  )
LIMIT
  1;

-- name: MfaGetAllMfaMethodsForUser :many
SELECT
  m.id AS id,
  m.status AS status,
  m.method_type AS method_type,
  m.user_id AS user_id,
  m.label AS label,
  e.email AS method_email_email,
  p.phone AS method_phone_phone,
  t.algorithm AS method_totp_algorithm
FROM
  mfa_method AS m
  LEFT JOIN mfa_method_type_email AS e ON e.id = m.id
  LEFT JOIN mfa_method_type_phone AS p ON p.id = m.id
  LEFT JOIN mfa_method_type_totp AS t ON t.id = m.id
WHERE
  m.user_id = @user_id::INT
  AND (
    sqlc.narg(method_type)::TEXT IS NULL
    OR m.method_type = @method_type::TEXT
  )
  AND (
    sqlc.narg(status)::TEXT IS NULL
    OR m.status = @status::TEXT
  );

-- name: MfaStartMfaSession :one
INSERT INTO
  mfa_session (user_id, purpose, expires_at)
VALUES
  (
    @user_id::INT,
    @purpose::TEXT,
    @expires_at::TIMESTAMPTZ
  )
RETURNING
  id;

-- name: MfaDeleteMfaSession :exec
DELETE FROM mfa_session
WHERE
  id = @id::UUID;

-- name: MfaRemoveExpiredMfaSession :exec
DELETE FROM mfa_session
WHERE
  expires_at < NOW();

-- name: MfaAddPendingMfaSession :exec
INSERT INTO
  pending_mfa_session (
    mfa_session,
    mfa_method,
    otp_challenge,
    expires_at
  )
VALUES
  (
    @mfa_session::UUID,
    @mfa_method::INT,
    sqlc.narg(otp_challenge)::UUID,
    @expires_at::TIMESTAMPTZ
  );

-- name: MfaGetPendingMfaSession :one
SELECT
  *
from
  pending_mfa_session
WHERE
  mfa_session = @mfa_session::UUID
  AND mfa_method = @mfa_method::INTEGER
LIMIT
  1;

-- name: MfaSetOtpChallengeForPendingMfa :exec
UPDATE pending_mfa_session
SET
  otp_challenge = @otp_challenge::UUID
WHERE
  mfa_session = @mfa_session::UUID
  AND mfa_method = @mfa_method::INTEGER;

-- name: MfaGetPendingMfaSessionWithOtpChallenge :one
SELECT
  p.mfa_session mfa_session,
  p.mfa_method mfa_method,
  p.expires_at pending_mfa_session_expires_at,
  p.created_at pending_mfa_session_created_at,
  p.updated_at AS pending_mfa_session_updated_at,
  o.id AS otp_challenge_id,
  o.otp_hash AS otp_challenge_otp_hash,
  o.channel AS otp_challenge_channel,
  o.attempts AS otp_challenge_attempts,
  o.purpose AS otp_challenge_purpose,
  o.created_at AS otp_challenge_created_at,
  o.updated_at AS otp_challenge_updated_at,
  o.expires_at AS otp_challenge_expires_at
from
  pending_mfa_session AS p
  LEFT JOIN otp_challenge AS o ON p.otp_challenge = o.id
WHERE
  p.mfa_session = @mfa_session::UUID
  AND p.mfa_method = @mfa_method::INTEGER
  AND o.expires_at > NOW()
LIMIT
  1;

-- name: MfaRemoveExpiredPendingMfaSession :exec
DELETE FROM pending_mfa_session
WHERE
  expires_at < NOW();

-- name: MfaUseBackupCode :exec
UPDATE backup_codes
SET
  used = TRUE
WHERE
  used = FALSE
  AND user_id = @user_id::INT
  AND code_hash = @code_hash::TEXT;

-- name: MfaDeleteAllBackupCodesForUser :exec
DELETE FROM backup_codes
WHERE
  user_id = @user_id::INT;

-- name: MfaInsertBackupCodes :copyfrom
INSERT INTO
  backup_codes (user_id, code_hash)
VALUES
  (@user_id::INT, @code_hash::TEXT);

-- name: MfaGetRememberedDevice :one
SELECT
  *
FROM
  mfa_remembered_devices
WHERE
  user_id = @user_id::INT
  AND device_fingerprint = @device_fingerprint::TEXT
  AND expires_at > NOW()
LIMIT
  1;

-- name: MfaRemoveExpiredRememberedDevices :exec
DELETE FROM mfa_remembered_devices
WHERE
  expires_at < NOW();

-- name: MfaGetRememberedDevices :many
SELECT
  *
FROM
  mfa_remembered_devices
WHERE
  user_id = @user_id::INT
  AND expires_at > NOW();

-- name: MfaRememberDevice :exec
INSERT INTO
  mfa_remembered_devices (user_id, device_fingerprint, expires_at)
VALUES
  (
    @user_id::INT,
    @device_fingerprint::TEXT,
    @expires_at::TIMESTAMPTZ
  );

-- name: MfaRemoveRememberDevice :exec
DELETE FROM mfa_remembered_devices
WHERE
  id = @id::UUID;

-- name: MfaUpdateLastUsedForRememberDevice :exec
UPDATE mfa_remembered_devices
SET
  last_used = @last_used::TIMESTAMPTZ
WHERE
  user_id = @user_id::INT
  AND device_fingerprint = @device_fingerprint::TEXT
  AND expires_at > NOW();

-- name: MfaCreateTypeTotp :one
WITH
  new_mfa_method AS (
    INSERT INTO
      mfa_method (status, method_type, user_id, label)
    VALUES
      ('pending', 'totp', @user_id::INT, @label::TEXT)
    RETURNING
      id
  )
INSERT INTO
  mfa_method_type_totp (id, secret_key, algorithm, digits, period, issuer)
VALUES
  (
    (
      SELECT
        id
      FROM
        new_mfa_method
    ),
    @secret_key::TEXT,
    @algorithm::TEXT,
    @digits::INT,
    @period::INT,
    @issuer::TEXT
  )
RETURNING
  id;

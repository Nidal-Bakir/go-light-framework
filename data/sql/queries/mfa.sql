-- name: MfaCreateTypeEmail :one
WITH
  new_mfa_method AS (
    INSERT INTO
      mfa_method (status, method_type, user_id, label)
    VALUES
      (
        'pending',
        'email',
        @user_id::INT,
        sqlc.narg (label)::TEXT
      )
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

-- name: MfaCreateTypePhone :one
WITH
  new_mfa_method AS (
    INSERT INTO
      mfa_method (status, method_type, user_id, label)
    VALUES
      (
        'pending',
        'phone',
        @user_id::INT,
        sqlc.narg (label)::TEXT
      )
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
  t.algorithm AS method_totp_algorithm,
  h.algorithm AS method_hotp_algorithm
FROM
  mfa_method AS m
  LEFT JOIN mfa_method_type_email AS e ON m.id = e.id
  LEFT JOIN mfa_method_type_phone AS p ON m.id = p.id
  LEFT JOIN mfa_method_type_totp AS t ON m.id = t.id
  LEFT JOIN mfa_method_type_hotp AS h ON m.id = h.id
WHERE
  m.id = @id::INT;

-- name: MfaGetAllMfaMethodsForUser :many
SELECT
  m.id AS id,
  m.status AS status,
  m.method_type AS method_type,
  m.user_id AS user_id,
  m.label AS label,
  e.email AS method_email_email,
  p.phone AS method_phone_phone,
  t.algorithm AS method_totp_algorithm,
  h.algorithm AS method_hotp_algorithm
FROM
  mfa_method AS m
  LEFT JOIN mfa_method_type_email AS e ON e.id = m.id
  LEFT JOIN mfa_method_type_phone AS p ON p.id = m.id
  LEFT JOIN mfa_method_type_totp AS t ON t.id = m.id
  LEFT JOIN mfa_method_type_hotp AS h ON h.id = m.id
WHERE
  m.user_id = @user_id::INT;

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
  )
RETURNING
  mfa_session;

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

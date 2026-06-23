-- name: InstallationCreateNewInstallation :exec
INSERT INTO
  installation (
    installation_token,
    notification_token,
    locale,
    timezone_offset_in_minutes,
    device_manufacturer,
    device_os,
    client_type,
    device_os_version,
    app_version
  )
VALUES
  ($1, $2, $3, $4, $5, $6, $7, $8, $9);


-- name: InstallationUpdateInstallation :exec
UPDATE installation
SET
  notification_token = $2,
  locale = $3,
  timezone_Offset_in_minutes = $4,
  app_version = $5
WHERE
  installation_token = $1
  AND deleted_at IS NULL;


-- name: InstallationSoftDeleteInstallation :exec
UPDATE installation
SET
  deleted_at = NOW()
WHERE
  id = $1;


-- name: InstallationGetInstallationUsingToken :one
SELECT
  *
FROM
  installation
WHERE
  installation_token = $1
  AND deleted_at IS NULL
LIMIT
  1;


-- name: InstallationGetInstallationUsingTokenAndWhereAttachTo :one
SELECT
  *
FROM
  installation
WHERE
  installation_token = $1
  AND attach_to = $2
  AND deleted_at IS NULL
LIMIT
  1;


-- name: InstallationAttachSessionToInstallationByToken :exec
UPDATE installation
SET
  attach_to = $2,
  last_attach_to = NULL
WHERE
  installation_token = $1
  AND attach_to IS NULL;


-- name: InstallationAttachSessionToInstallationById :execrows
UPDATE installation
SET
  attach_to = $2,
  last_attach_to = NULL
WHERE
  id = $1
  AND attach_to IS NULL;


-- name: InstallationDetachSessionFromInstallationByToken :exec
UPDATE installation
SET
  attach_to = NULL,
  last_attach_to = $2
WHERE
  installation_token = $1;


-- name: InstallationDetachSessionFromInstallationById :exec
UPDATE installation
SET
  attach_to = NULL,
  last_attach_to = $2
WHERE
  id = $1;


-- name: InstallationDetachSessionFromInstallationByUserId :exec
UPDATE installation AS i
SET
  attach_to = NULL,
  last_attach_to = s.id
FROM
  active_session AS s
  JOIN active_login_identity AS li ON s.originated_from = li.id
WHERE
  li.user_id = $1
  AND i.attach_to = s.id
  AND i.last_attach_to IS NULL
  AND i.deleted_at IS NULL;


-------------------------------------------------------------------
-------------------------------------------------------------------
-------------------------------------------------------------------
-- name: LoginIdentityCreateNewUserAndPasswordLoginIdentity :one
WITH
  new_user AS (
    INSERT INTO
      users (
        username,
        profile_image,
        first_name,
        last_name,
        role_name
      )
    VALUES
      (
        @user_username::text,
        sqlc.narg(user_profile_image)::text,
        @user_first_name::text,
        sqlc.narg(user_last_name)::text,
        sqlc.narg(user_role_name)::text
      )
    RETURNING
      *
  ),
  new_identity AS (
    INSERT INTO
      login_identity (user_id, identity_type)
    VALUES
      (
        (
          SELECT
            id
          FROM
            new_user
        ),
        @identity_type::text
      )
    RETURNING
      id
  ),
  final_insert AS (
    INSERT INTO
      password_login_identity (
        login_identity_id,
        email,
        phone,
        hashed_pass,
        pass_salt,
        verified_at
      )
    VALUES
      (
        (
          SELECT
            id
          FROM
            new_identity
        ),
        sqlc.narg(password_email)::text,
        sqlc.narg(password_phone)::text,
        @password_hashed_pass::text,
        @password_pass_salt::text,
        @password_verified_at::timestamptz
      )
  )
SELECT
  *
FROM
  new_user;


-- name: LoginIdentityCreateNewPasswordLoginIdentity :one
WITH
  new_identity AS (
    INSERT INTO
      login_identity (user_id, identity_type)
    VALUES
      (@identity_user_id::int, @identity_type::text)
    RETURNING
      id
  )
INSERT INTO
  password_login_identity (
    login_identity_id,
    email,
    phone,
    hashed_pass,
    pass_salt,
    verified_at
  )
VALUES
  (
    (
      SELECT
        id
      FROM
        new_identity
    ),
    sqlc.narg(password_email)::text,
    sqlc.narg(password_phone)::text,
    @password_hashed_pass::text,
    @password_pass_salt::text,
    @password_verified_at::timestamptz
  )
RETURNING
  id AS password_login_identity_id,
  (
    SELECT
      id AS login_identity_id
    FROM
      new_identity
  );


-- name: LoginIdentityGetOIDCDataBySub :one
SELECT
  u.id AS user_id,
  u.username AS user_username,
  u.profile_image AS user_profile_image,
  u.first_name AS user_first_name,
  u.middle_name AS user_middle_name,
  u.last_name AS user_last_name,
  u.blocked_at AS user_blocked_at,
  u.blocked_until AS user_blocked_until,
  u.created_at AS user_created_at,
  u.updated_at AS user_updated_at,
  u.role_name AS user_role_name,
  li.id AS login_identity_id,
  od.provider_name AS oauth_provider_name,
  od.id AS oidc_data_id
FROM
  active_oidc_data AS od
  JOIN active_oidc_login_identity AS oli ON od.id = oli.oidc_data_id
  JOIN active_login_identity AS li ON oli.login_identity_id = li.id
  JOIN users AS u ON li.user_id = u.id
WHERE
  od.sub = @oidc_sub::text
  AND li.identity_type = 'oidc'
  AND od.provider_name = @oidc_provider_name::text
  AND u.deleted_at IS NULL
LIMIT
  1;


-- name: LoginIdentityGetPasswordLoginIdentity :one
SELECT
  li.id AS login_identity_id,
  li.user_id,
  li.identity_type,
  li.is_primary AS login_identity_is_primary,
  li.last_used_at AS login_identity_last_used_at,
  pli.id AS password_login_identity_id,
  pli.email,
  pli.phone,
  pli.hashed_pass,
  pli.pass_salt,
  pli.verified_at
FROM
  active_login_identity AS li
  JOIN active_password_login_identity pli ON li.id = pli.login_identity_id
WHERE
  li.identity_type = @identity_type::text
  AND (
    (
      @identity_type::text = 'email'
      AND pli.email = @identity_value::text
    )
    OR (
      @identity_type::text = 'phone'
      AND pli.phone = @identity_value::text
    )
  )
LIMIT
  1;


-- name: LoginIdentityGetPasswordLoginIdentityWithUser :one
SELECT
  li.id AS login_identity_id,
  li.identity_type,
  li.is_primary,
  li.last_used_at,
  pli.id AS password_login_identity_id,
  pli.email,
  pli.phone,
  pli.hashed_pass,
  pli.pass_salt,
  pli.verified_at,
  u.id AS user_id,
  u.username AS user_username,
  u.profile_image AS user_profile_image,
  u.first_name AS user_first_name,
  u.middle_name AS user_middle_name,
  u.last_name AS user_last_name,
  u.blocked_at AS user_blocked_at,
  u.blocked_until AS user_blocked_until,
  u.role_name AS user_role_name
FROM
  users AS u
  JOIN active_login_identity AS li ON u.id = li.user_id
  JOIN active_password_login_identity pli ON li.id = pli.login_identity_id
WHERE
  li.identity_type = @identity_type::text
  AND u.deleted_at IS NULL
  AND (
    (
      @identity_type::text = 'email'
      AND pli.email = @identity_value::text
    )
    OR (
      @identity_type::text = 'phone'
      AND pli.phone = @identity_value::text
    )
  )
LIMIT
  1;


-- name: LoginIdentityGetAllByUserId :many
SELECT
  li.id AS login_identity_id,
  li.user_id AS login_identity_user_id,
  li.identity_type AS login_identity_identity_type,
  li.is_primary AS login_identity_is_primary,
  li.last_used_at AS login_identity_last_used_at,
  -- Password-based
  pli.id AS password_id,
  pli.email AS password_email,
  pli.phone AS password_phone,
  pli.hashed_pass AS password_hashed_pass,
  pli.pass_salt AS password_pass_salt,
  pli.verified_at AS password_verified_at,
  -- Guest-based
  gli.id AS guest_id,
  gli.device_id AS guest_device_id,
  -- OIDC-based
  oidc_data.id AS oidc_data_id,
  oidc_data.sub AS oidc_data_sub,
  oidc_data.email AS oidc_data_email,
  oidc_data.iss AS oidc_data_issuer,
  oidc_data.aud AS oidc_data_audience,
  oidc_data.given_name AS oidc_data_given_name,
  oidc_data.family_name AS oidc_data_family_name,
  oidc_data.name AS oidc_data_name,
  oidc_data.picture AS oidc_data_picture,
  oidc_data.provider_name AS oauth_provider_name
FROM
  active_login_identity AS li
  LEFT JOIN active_password_login_identity AS pli ON li.id = pli.login_identity_id
  LEFT JOIN active_guest_login_identity AS gli ON li.id = gli.login_identity_id
  LEFT JOIN active_oidc_login_identity AS oli ON li.id = oli.login_identity_id
  LEFT JOIN active_oidc_data AS oidc_data ON oli.oidc_data_id = oidc_data.id
WHERE
  li.user_id = $1
ORDER BY
  li.is_primary DESC,
  li.last_used_at DESC;


-- name: LoginIdentityGetAllPasswordLoginIdentitiesByUserId :many
SELECT
  li.id AS login_identity_id,
  li.user_id AS login_identity_user_id,
  li.identity_type AS login_identity_identity_type,
  li.is_primary AS login_identity_is_primary,
  li.last_used_at AS login_identity_last_used_at,
  -- Password-based
  pli.id AS password_id,
  pli.email AS password_email,
  pli.phone AS password_phone,
  pli.hashed_pass AS password_hashed_pass,
  pli.pass_salt AS password_pass_salt,
  pli.verified_at AS password_verified_at
FROM
  active_login_identity AS li
  LEFT JOIN active_password_login_identity AS pli ON li.id = pli.login_identity_id
WHERE
  li.user_id = $1
ORDER BY
  li.is_primary DESC,
  li.last_used_at DESC;


-- name: LoginIdentityChangePasswordLoginIdentityByUserId :exec
UPDATE password_login_identity pli
SET
  hashed_pass = $2,
  pass_salt = $3
FROM
  active_login_identity li
WHERE
  pli.login_identity_id = li.id
  AND li.user_id = $1;


-- name: LoginIdentityIsEmailUsed :one
SELECT
  COUNT(*)
FROM
  active_password_login_identity
WHERE
  email = $1;


-- name: LoginIdentityIsPhoneUsed :one
SELECT
  COUNT(*)
FROM
  active_password_login_identity
WHERE
  phone = $1;


-- name: LoginIdentityIsOidcEmailUsed :one
SELECT
  COUNT(*)
FROM
  active_oidc_data
WHERE
  email = $1;


-- name: LoginIdentityUpdateLastUsedAtToNow :exec
UPDATE login_identity
SET
  last_used_at = NOW()
WHERE
  id = @id;


-- name: LoginIdentityCreateNewUserAndOIDCLoginIdentity :one
WITH
  new_user AS (
    INSERT INTO
      users (
        username,
        profile_image,
        first_name,
        last_name,
        role_name
      )
    VALUES
      (
        @user_username::text,
        sqlc.narg(user_profile_image)::text,
        @user_first_name::text,
        sqlc.narg(user_last_name)::text,
        sqlc.narg(user_role_name)::text
      )
    RETURNING
      id AS user_id,
      username,
      profile_image,
      first_name,
      middle_name,
      last_name,
      created_at,
      updated_at,
      blocked_at,
      blocked_until,
      deleted_at,
      role_name
  ),
  new_identity AS (
    INSERT INTO
      login_identity (user_id, identity_type)
    VALUES
      (
        (
          SELECT
            user_id
          FROM
            new_user
        ),
        'oidc'
      )
    RETURNING
      id
  ),
  oauth_provider_record AS (
    SELECT
      @oauth_provider_name::text AS provider_name,
      @oauth_provider_is_oidc_capable::bool AS is_oidc_capable
  ),
  oauth_provider_record_merge_op AS (
    MERGE INTO oauth_provider AS target USING oauth_provider_record AS r ON target.name = r.provider_name
    AND target.is_oidc_capable = r.is_oidc_capable WHEN NOT MATCHED THEN INSERT (name, is_oidc_capable)
    VALUES
      (r.provider_name, r.is_oidc_capable)
  ),
  oauth_connection_record AS (
    SELECT
      (
        SELECT
          provider_name
        FROM
          oauth_provider_record
      ) AS provider_name,
      @oauth_scopes::TEXT[] AS scopes
  ),
  oauth_connection_record_merge_op AS (
    MERGE INTO oauth_connection AS target USING oauth_connection_record AS r ON target.provider_name = r.provider_name
    AND target.scopes = r.scopes WHEN NOT MATCHED THEN INSERT (provider_name, scopes)
    VALUES
      (r.provider_name, r.scopes)
    RETURNING
      target.*
  ),
  oauth_connection_row AS (
    SELECT
      id,
      provider_name,
      scopes,
      created_at,
      updated_at,
      deleted_at
    FROM
      oauth_connection_record_merge_op
    UNION ALL
    SELECT
      id,
      provider_name,
      scopes,
      created_at,
      updated_at,
      deleted_at
    FROM
      oauth_connection
    WHERE
      provider_name = (
        SELECT
          provider_name
        FROM
          oauth_provider_record
      )
      AND scopes = (
        SELECT
          scopes
        FROM
          oauth_connection_record
      )
  ),
  new_oauth_integration AS (
    INSERT INTO
      oauth_integration (oauth_connection_id, integration_type)
    VALUES
      (
        (
          SELECT
            id
          FROM
            oauth_connection_row
        ),
        'user'
      )
    RETURNING
      id
  ),
  new_oauth_token AS (
    INSERT INTO
      oauth_token (
        oauth_integration_id,
        access_token,
        refresh_token,
        token_type,
        expires_at,
        issued_at
      )
    SELECT
      (
        SELECT
          id
        FROM
          new_oauth_integration
      ),
      sqlc.narg(oauth_access_token)::text,
      sqlc.narg(oauth_refresh_token)::text,
      sqlc.narg(oauth_token_type)::text,
      @oauth_token_expires_at::timestamp,
      @oauth_token_issued_at::timestamp
    WHERE
      (
        sqlc.narg(oauth_access_token)::text IS NOT NULL
        AND sqlc.narg(oauth_access_token)::text <> ''
      )
      OR (
        sqlc.narg(oauth_refresh_token)::text IS NOT NULL
        AND sqlc.narg(oauth_refresh_token)::text <> ''
      )
  ),
  new_user_integration AS (
    INSERT INTO
      user_integration (oauth_integration_id, user_id)
    VALUES
      (
        (
          SELECT
            id
          FROM
            new_oauth_integration
        ),
        (
          SELECT
            user_id
          FROM
            new_user
        )
      )
    RETURNING
      id
  ),
  new_oidc_data AS (
    INSERT INTO
      oidc_data (
        provider_name,
        sub,
        email,
        iss,
        aud,
        given_name,
        family_name,
        name,
        picture
      )
    VALUES
      (
        (
          SELECT
            provider_name
          FROM
            oauth_provider_record
        ),
        @oidc_sub::text,
        sqlc.narg(oidc_email)::text,
        @oidc_iss::text,
        @oidc_aud::text,
        sqlc.narg(oidc_given_name)::text,
        sqlc.narg(oidc_family_name)::text,
        sqlc.narg(oidc_name)::text,
        sqlc.narg(oidc_picture)::text
      )
    RETURNING
      id
  ),
  new_oidc_login_identity AS (
    INSERT INTO
      oidc_login_identity (login_identity_id, oidc_data_id)
    VALUES
      (
        (
          SELECT
            id
          FROM
            new_identity
        ),
        (
          SELECT
            id
          FROM
            new_oidc_data
        )
      )
  )
SELECT
  u.user_id,
  u.username,
  u.profile_image,
  u.first_name,
  u.middle_name,
  u.last_name,
  u.created_at,
  u.updated_at,
  u.blocked_at,
  u.blocked_until,
  u.deleted_at,
  u.role_name,
  i.id AS new_login_identity_id
FROM
  new_user AS u,
  new_identity AS i;


-------------------------------------------------------------------
-------------------------------------------------------------------
-------------------------------------------------------------------
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
    sqlc.narg (status)::TEXT IS NULL
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
    sqlc.narg (status)::TEXT IS NULL
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
    sqlc.narg (method_type)::TEXT IS NULL
    OR m.method_type = @method_type::TEXT
  )
  AND (
    sqlc.narg (status)::TEXT IS NULL
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
    sqlc.narg (otp_challenge)::UUID,
    @expires_at::TIMESTAMPTZ
  );


-- name: MfaGetPendingMfaSession :one
SELECT
  p.mfa_session,
  p.mfa_method,
  p.otp_challenge,
  m.status,
  m.method_type,
  t.secret_key AS totp_secret_key
FROM
  pending_mfa_session AS p
  JOIN mfa_method AS m ON m.id = p.mfa_method
  LEFT JOIN mfa_method_type_totp AS t ON t.id = m.id
WHERE
  p.mfa_session = @mfa_session::UUID
  AND p.mfa_method = @mfa_method::INTEGER
  AND p.expires_at > NOW()
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
  p.mfa_session,
  p.mfa_method,
  p.expires_at AS pending_mfa_session_expires_at,
  p.created_at AS pending_mfa_session_created_at,
  p.updated_at AS pending_mfa_session_updated_at,
  o.id AS otp_challenge_id,
  o.otp_hash AS otp_challenge_otp_hash,
  o.channel AS otp_challenge_channel,
  o.attempts AS otp_challenge_attempts,
  o.purpose AS otp_challenge_purpose,
  o.created_at AS otp_challenge_created_at,
  o.updated_at AS otp_challenge_updated_at,
  o.expires_at AS otp_challenge_expires_at
FROM
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


-------------------------------------------------------------------
-------------------------------------------------------------------
-------------------------------------------------------------------
-- name: OauthCreateConnectionWithIntegrationDataAndTokens :exec
WITH
  oauth_connection_record AS (
    SELECT
      @provider_name::text AS provider_name,
      @scopes::TEXT[] AS scopes
  ),
  oauth_connection_record_merge_op AS (
    MERGE INTO oauth_connection AS target USING oauth_connection_record AS r ON target.provider_name = r.provider_name
    AND target.scopes = r.scopes WHEN NOT MATCHED THEN INSERT (provider_name, scopes)
    VALUES
      (r.provider_name, r.scopes)
    RETURNING
      target.*
  ),
  oauth_connection_row AS (
    SELECT
      id,
      provider_name,
      scopes,
      created_at,
      updated_at,
      deleted_at
    FROM
      oauth_connection_record_merge_op
    UNION ALL
    SELECT
      id,
      provider_name,
      scopes,
      created_at,
      updated_at,
      deleted_at
    FROM
      oauth_connection
    WHERE
      provider_name = (
        SELECT
          provider_name
        FROM
          oauth_connection_record
      )
      AND scopes = (
        SELECT
          scopes
        FROM
          oauth_connection_record
      )
  ),
  new_oauth_integration AS (
    INSERT INTO
      oauth_integration (oauth_connection_id, integration_type)
    VALUES
      (
        (
          SELECT
            id
          FROM
            oauth_connection_row
        ),
        'user'
      )
    RETURNING
      id
  ),
  new_oauth_token AS (
    INSERT INTO
      oauth_token (
        oauth_integration_id,
        access_token,
        refresh_token,
        token_type,
        expires_at,
        issued_at
      )
    SELECT
      (
        SELECT
          id
        FROM
          new_oauth_integration
      ),
      sqlc.narg(access_token)::text,
      sqlc.narg(refresh_token)::text,
      sqlc.narg(token_type)::text,
      @expires_at::timestamp,
      @issued_at::timestamp
    WHERE
      (
        sqlc.narg(access_token)::text IS NOT NULL
        AND sqlc.narg(access_token)::text <> ''
      )
      OR (
        sqlc.narg(refresh_token)::text IS NOT NULL
        AND sqlc.narg(refresh_token)::text <> ''
      )
  )
INSERT INTO
  user_integration (oauth_integration_id, user_id)
VALUES
  (
    (
      SELECT
        id
      FROM
        new_oauth_integration
    ),
    @user_id::int
  );


-------------------------------------------------------------------
-------------------------------------------------------------------
-------------------------------------------------------------------
-- name: OauthConnectionCreate :one
INSERT INTO
  oauth_connection (provider_name, scopes)
VALUES
  (@provider_name::text, @scopes::TEXT[])
RETURNING
  *;


-------------------------------------------------------------------
-------------------------------------------------------------------
-------------------------------------------------------------------
-- name: OauthIntegrationUpdateToOauthConnectionBasedOnNewScopes :exec
WITH
  oauth_connection_record AS (
    SELECT
      @provider_name::text AS provider_name,
      @oauth_scopes::TEXT[] AS scopes
  ),
  oauth_connection_record_merge_op AS (
    MERGE INTO oauth_connection AS target USING oauth_connection_record AS r ON target.provider_name = r.provider_name
    AND target.scopes = r.scopes WHEN NOT MATCHED THEN INSERT (provider_name, scopes)
    VALUES
      (r.provider_name, r.scopes)
  ),
  oauth_connection_row AS (
    SELECT
      *
    FROM
      oauth_connection
    WHERE
      provider_name = @provider_name::text
      AND scopes = @oauth_scopes::TEXT[]
  )
UPDATE oauth_integration
SET
  oauth_connection_id = (
    SELECT
      id
    FROM
      oauth_connection_row
  )
WHERE
  id = @integration_id::int;


-- name: OauthIntegrationGetByUserAndScopes :one
SELECT
  ui.id AS user_integration_id,
  ui.user_id AS user_integration_user_id,
  oi.id AS oauth_integration_id,
  oi.id AS oauth_integration_type,
  ot.id AS oauth_token_id,
  oc.id AS oauth_connection_id,
  oc.scopes AS oauth_connection_scopes,
  oc.provider_name AS oauth_connection_provider_name
FROM
  active_user_integration AS ui
  JOIN active_oauth_integration AS oi ON ui.oauth_integration_id = oi.id
  JOIN active_oauth_connection AS oc ON oi.oauth_connection_id = oc.id
  LEFT JOIN active_oauth_token AS ot ON ot.oauth_integration_id = oi.id
WHERE
  ui.user_id = @user_id::INTEGER
  AND oc.scopes = @oauth_scopes::TEXT[]
  AND oc.provider_name = @provider_name::text
LIMIT
  1;


-------------------------------------------------------------------
-------------------------------------------------------------------
-------------------------------------------------------------------
-- name: OauthTokenUpdate :exec
UPDATE oauth_token
SET
  access_token = sqlc.narg(access_token)::text,
  refresh_token = sqlc.narg(refresh_token)::text,
  token_type = sqlc.narg(token_type)::text,
  expires_at = @expires_at,
  issued_at = @issued_at
WHERE
  id = @id;


-- name: OauthTokenCreate :exec
INSERT INTO
  oauth_token (
    oauth_integration_id,
    access_token,
    refresh_token,
    token_type,
    expires_at,
    issued_at
  )
VALUES
  (
    @oauth_integration_id,
    sqlc.narg(access_token)::text,
    sqlc.narg(refresh_token)::text,
    sqlc.narg(token_type)::text,
    @expires_at,
    @issued_at
  );


-------------------------------------------------------------------
-------------------------------------------------------------------
-------------------------------------------------------------------
-- name: OidcDataUpdateRecored :exec
UPDATE oidc_data
SET
  email = sqlc.narg(email)::text,
  given_name = sqlc.narg(given_name)::text,
  family_name = sqlc.narg(family_name)::text,
  name = sqlc.narg(name)::text,
  picture = sqlc.narg(picture)::text
WHERE
  id = @id;


-------------------------------------------------------------------
-------------------------------------------------------------------
-------------------------------------------------------------------
-- name: OtpChallengeInsert :one
INSERT INTO
  otp_challenge (
    id,
    otp_hash,
    attempts,
    channel,
    purpose,
    expires_at
  )
VALUES
  (
    sqlc.narg(id),
    @otp_hash,
    @attempts,
    @channel,
    @purpose,
    @expires_at
  )
RETURNING
  id;


-- name: OtpChallengeGet :one
SELECT
  *
FROM
  otp_challenge
WHERE
  id = @id
  AND expires_at < NOW()
LIMIT
  1;


-- name: OtpChallengeIncAttempt :one
UPDATE otp_challenge
SET
  attempts = attempts + @inc
WHERE
  id = @id
  AND attempts < @attemptsLimit
  AND expires_at > NOW()
RETURNING
  attempts;


-- name: OtpChallengeDelete :exec
DELETE FROM otp_challenge
WHERE
  id = @id;


-- name: OtpChallengeDeleteExpiredRows :exec
DELETE FROM otp_challenge
WHERE
  expires_at <= NOW();


-------------------------------------------------------------------
-------------------------------------------------------------------
-------------------------------------------------------------------
-- name: PermGetAllPermissions :many
SELECT
  name,
  created_at,
  updated_at
FROM
  permission;


-- name: PermGetAllRoles :many
SELECT
  name,
  created_at,
  updated_at
FROM
  role;


-- name: PermGetRoleWithItsPermissions :many
SELECT
  r.name AS role_name,
  p.name AS permission_name
FROM
  role AS r
  JOIN role_permission AS rp ON r.name = rp.role_name
  JOIN permission AS p ON p.name = rp.permission_name
WHERE
  r.name = $1;


-- name: PermCreateNewPermission :one
INSERT INTO
  permission (name)
VALUES
  ($1)
RETURNING
  *;


-- name: PermCreateNewPermissions :copyfrom
INSERT INTO
  permission (name)
VALUES
  ($1);


-- name: PermCreateNewRole :one
INSERT INTO
  role (name)
VALUES
  ($1)
RETURNING
  *;


-- name: PermCreateNewRoles :copyfrom
INSERT INTO
  role (name)
VALUES
  ($1);


-- name: PermAddPermissionToRole :exec
INSERT INTO
  role_permission (role_name, permission_name)
VALUES
  ($1, $2);


-- name: PermAddPermissionsToRoles :copyfrom
INSERT INTO
  role_permission (role_name, permission_name)
VALUES
  ($1, $2);


-- name: PermRemovePermissionFromRole :exec
DELETE FROM role_permission
WHERE
  role_name = $1
  AND permission_name = $2;


-- name: PermSoftDeletePermission :exec
UPDATE permission
SET
  deleted_at = NOW()
WHERE
  name = $1;


-- name: PermSoftDeleteRole :exec
UPDATE role
SET
  deleted_at = NOW()
WHERE
  name = $1;


-------------------------------------------------------------------
-------------------------------------------------------------------
-------------------------------------------------------------------
-- name: SeederVersionAddValue :exec
INSERT INTO
  seeder_version (version)
VALUES
  ($1);


-- name: SeederVersionReadLatestAppliedVersion :one
SELECT
  version
FROM
  seeder_version
ORDER BY
  version DESC
LIMIT
  1;


-------------------------------------------------------------------
-------------------------------------------------------------------
-------------------------------------------------------------------
-- name: SessionCreateNewSession :one
INSERT INTO
  session (
    token,
    originated_from,
    used_installation,
    expires_at,
    ip_address,
    purpose
  )
VALUES
  (
    @token::text,
    @originated_from::int,
    @used_installation::int,
    @expires_at::timestamptz,
    @ip_address::INET,
    @purpose::text
  )
RETURNING
  id;


-- name: SessionGetActiveSessionById :one
SELECT
  *
FROM
  active_session
WHERE
  id = $1
LIMIT
  1;


-- name: SessionGetActiveSessionByToken :one
SELECT
  *
FROM
  active_session
WHERE
  token = $1
LIMIT
  1;


-- name: SessionDeleteSession :exec
DELETE FROM session
WHERE
  id = $1;


-- name: SessionSoftDeleteSession :exec
UPDATE session
SET
  deleted_at = NOW()
WHERE
  id = $1;


-- name: SessionDeleteAllActiveSessionsForUser :exec
DELETE FROM session AS s USING active_login_identity AS li
WHERE
  s.originated_from = li.id
  AND li.user_id = @user_id::int;


-- name: SessionDeleteExpiredRows :exec
DELETE FROM active_session
WHERE
  expires_at <= NOW();


-------------------------------------------------------------------
-------------------------------------------------------------------
-------------------------------------------------------------------
-- name: SessionStoreStoreAttr :exec
INSERT INTO
  session_store (session, attr_key, attr_value, expires_at)
VALUES
  (
    @session::TEXT,
    @attr_key::TEXT,
    @attr_value::TEXT,
    @expires_at::timestamptz
  );


-- name: SessionStoreStoreAttrs :copyfrom
INSERT INTO
  session_store (session, attr_key, attr_value, expires_at)
VALUES
  (
    @session::TEXT,
    @attr_key::TEXT,
    @attr_value::TEXT,
    @expires_at::timestamptz
  );


-- name: SessionStoreGetAttr :one
SELECT
  attr_value
FROM
  session_store
WHERE
  session = @session::TEXT
  AND attr_key = @attr_key::TEXT
LIMIT
  1;


-- name: SessionStoreRemoveAttr :exec
DELETE FROM session_store
WHERE
  session = @session::TEXT
  AND attr_key = @attr_key::TEXT;


-- name: SessionStoreDeleteExpiredRows :exec
DELETE FROM session_store
WHERE
  expires_at <= NOW();


-------------------------------------------------------------------
-------------------------------------------------------------------
-------------------------------------------------------------------
-- name: SettingsGetByLable :one
SELECT
  *
FROM
  settings
WHERE
  label = @label::TEXT
LIMIT
  1;


-- name: SettingsDeleteByLable :exec
DELETE FROM settings
WHERE
  label = @label::TEXT;


-- name: SettingsSetSetting :exec
INSERT INTO
  settings (label, value)
VALUES
  (@label::TEXT, sqlc.narg(value)::TEXT)
ON CONFLICT (label) DO UPDATE
SET
  value = EXCLUDED.value;


-- name: SettingsCreateLabel :exec
INSERT INTO
  settings (label)
VALUES
  (@label::TEXT)
ON CONFLICT (label) DO NOTHING;


-------------------------------------------------------------------
-------------------------------------------------------------------
-------------------------------------------------------------------
-- name: UsersGetUserById :one
SELECT
  u.id,
  u.username,
  u.profile_image,
  u.first_name,
  u.middle_name,
  u.last_name,
  u.blocked_at,
  u.blocked_until,
  u.created_at,
  u.updated_at,
  u.role_name
FROM
  users AS u
WHERE
  id = $1
  AND u.deleted_at IS NULL
LIMIT
  1;


-- name: UsersGetUserAndSessionDataBySessionToken :one
SELECT
  s.id AS session_id,
  s.token AS session_token,
  s.originated_from AS session_originated_from,
  s.used_installation AS session_used_installation,
  s.purpose AS session_purpose,
  u.id AS user_id,
  u.username AS user_username,
  u.profile_image AS user_profile_image,
  u.first_name AS user_first_name,
  u.middle_name AS user_middle_name,
  u.last_name AS user_last_name,
  u.blocked_at AS user_blocked_at,
  u.blocked_until AS user_blocked_until,
  u.role_name AS user_role_name
FROM
  active_session AS s
  JOIN active_login_identity AS li ON s.originated_from = li.id
  JOIN users AS u ON u.id = li.user_id
WHERE
  s.token = @ token::text
  AND u.deleted_at IS NULL
  AND s.purpose = @ token_purpose::text
LIMIT
  1;


-- name: UsersIsUsernameUsed :one
SELECT
  COUNT(*)
FROM
  users
WHERE
  username = $1;


-- name: UsersCreateNewUser :one
INSERT INTO
  users (
    username,
    profile_image,
    first_name,
    last_name,
    role_name
  )
VALUES
  ($1, $2, $3, $4, $5)
RETURNING
  *;


-- name: UsersUpdateUserData :one
UPDATE users
SET
  username = $2,
  profile_image = $3,
  first_name = $4,
  last_name = $5,
  role_name = $6
WHERE
  id = $1
RETURNING
  *;


-- name: UsersUpdateUsernameForUser :exec
UPDATE users
SET
  username = $2
WHERE
  id = $1;


-- name: UsersSoftDeleteUser :exec
UPDATE users
SET
  deleted_at = NOW()
WHERE
  id = $1;


-------------------------------------------------------------------
-------------------------------------------------------------------
-------------------------------------------------------------------

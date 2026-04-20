-- name: SessionCreateNewSession :one
INSERT INTO session (
        token,
        originated_from,
        used_installation,
        expires_at,
        ip_address,
        purpose
    )
VALUES (
    @token::text,
    @originated_from::int,
    @used_installation::int,
    @expires_at::timestamptz,
    @ip_address::INET,
    @purpose::text
)
RETURNING id;

-- name: SessionGetActiveSessionById :one
SELECT *
FROM active_session
WHERE id = $1
LIMIT 1;

-- name: SessionGetActiveSessionByToken :one
SELECT *
FROM active_session
WHERE token = $1
LIMIT 1;

-- name: SessionDeleteSession :exec
DELETE FROM session
WHERE id = $1;

-- name: SessionSoftDeleteSession :exec
UPDATE session SET
deleted_at = NOW()
WHERE id = $1;

-- name: SessionDeleteAllActiveSessionsForUser :exec
DELETE FROM session AS s
USING active_login_identity AS li
WHERE s.originated_from = li.id
AND li.user_id = @user_id::int;

-- name: SessionDeleteExpiredRows :exec
DELETE FROM active_session
WHERE expires_at <= NOW();

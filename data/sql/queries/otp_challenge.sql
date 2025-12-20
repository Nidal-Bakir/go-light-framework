-- name: OtpChallengeInsert :one
INSERT INTO otp_challenge (
    otp_hash,
    channel,
    attempts,
    expires_at
)
VALUES (
    @otp_hash,
    @channel,
    @attempts,
    @expires_at
)
RETURNING *;

-- name: OtpChallengeGet :one
SELECT *
FROM otp_challenge
WHERE id = @id
LIMIT 1;

-- name: OtpChallengeIncAttempt :one
UPDATE otp_challenge
SET attempts = attempts + @inc
WHERE id = @id
  AND attempts <= @attemptsLimit
RETURNING attempts;
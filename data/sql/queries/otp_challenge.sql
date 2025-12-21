-- name: OtpChallengeInsert :one
INSERT INTO otp_challenge (
    otp_hash,
    channel,
    purpose,
    expires_at
)
VALUES (
    @otp_hash,
    @channel,
    @purpose,
    @expires_at
)
RETURNING id;

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


-- name: OtpChallengeDelete :exec
DELETE
FROM otp_challenge
WHERE id = @id;

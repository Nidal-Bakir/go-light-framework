-- name: OtpChallengeInsert :one
INSERT INTO otp_challenge (
    otp_hash,
    attempts,
    channel,
    purpose,
    expires_at
)
VALUES (
    @otp_hash,
    @attempts,
    @channel,
    @purpose,
    @expires_at
)
RETURNING id;

-- name: OtpChallengeGet :one
SELECT *
FROM otp_challenge
WHERE id = @id 
    AND expires_at < NOW()
LIMIT 1;

-- name: OtpChallengeIncAttempt :one
UPDATE otp_challenge
SET attempts = attempts + @inc
WHERE id = @id 
 AND attempts < @attemptsLimit
 AND expires_at < NOW()
RETURNING attempts;


-- name: OtpChallengeDelete :exec
DELETE
FROM otp_challenge
WHERE id = @id;

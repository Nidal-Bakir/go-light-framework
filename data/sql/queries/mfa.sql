-- name: MfaCreateTypeEmail :one
WITH new_mfa_method AS(
    INSERT INTO mfa_method (
        status,
        method_type,
        user_id,
        label
        )
    VALUES (
        'pending',
        'email',
        @user_id::int,
        sqlc.narg(label)::text
    )
    RETURNING id
)
INSERT INTO mfa_method_type_email (
    id,
    ownership_verification,
    email
    )
VALUES (
    (SELECT id from new_mfa_method),
    @ownership_verification::uuid,
    @email::text
)
RETURNING id;

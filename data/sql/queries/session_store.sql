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

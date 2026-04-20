-- +goose Up
ALTER TABLE session
ADD used_installation INTEGER NOT NULL REFERENCES installation (id);

CREATE VIEW active_session AS
SELECT
  *
FROM
  session
WHERE
  deleted_at IS NULL
  AND expires_at > NOW();

-- +goose Down
DROP VIEW active_session;

ALTER TABLE session
DROP COLUMN used_installation;

-- name: RevokeToken :one
-- RevokeToken adds a token's JTI (JWT ID) to the revocation list.
INSERT INTO revoked_tokens (
  id,
  user_id,
  original_expires_at
) VALUES (
  ?, ?, ?
)
RETURNING *;

-- name: IsTokenRevoked :one
-- IsTokenRevoked checks if a token's JTI exists in the revocation list.
-- sqlc will generate a method that returns a boolean.
SELECT EXISTS(
  SELECT 1 FROM revoked_tokens WHERE id = ?
);

-- name: DeleteExpiredRevokedTokens :exec
-- DeleteExpiredRevokedTokens purges tokens from the revocation list
-- after they would have naturally expired. This keeps the table clean.
DELETE FROM revoked_tokens
WHERE original_expires_at <= strftime('%s', 'now');
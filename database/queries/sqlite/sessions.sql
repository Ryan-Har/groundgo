-- name: CreateSession :one
-- CreateSession creates a new session record for a user.
INSERT INTO sessions (
  id,
  user_id,
  expires_at,
  ip_address,
  user_agent
) VALUES (
  ?, ?, ?, ?, ?
)
RETURNING *;

-- name: GetSession :one
-- GetSession retrieves a single, active session by its ID.
-- It will not return a session if it has expired.
SELECT * FROM sessions
WHERE id = ? AND expires_at > strftime('%s', 'now');

-- name: DeleteSession :exec
-- DeleteSession removes a specific session, effectively logging the user out.
DELETE FROM sessions
WHERE id = ?;

-- name: DeleteSessionsByUserID :exec
-- DeleteSessionsByUserID removes all active sessions for a given user.
-- This is useful for "log out from all other devices" functionality.
DELETE FROM sessions
WHERE user_id = ?;

-- name: DeleteExpiredSessions :exec
-- DeleteExpiredSessions purges all session records that have passed their expiration time.
-- This should be run periodically by a background job.
DELETE FROM sessions
WHERE expires_at <= strftime('%s', 'now');

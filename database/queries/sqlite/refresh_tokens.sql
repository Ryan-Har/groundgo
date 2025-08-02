-- --
-- ## Refresh Token Queries
--
-- This file defines the SQLC queries for managing user refresh tokens.
-- A refresh token is a long-lived credential used to obtain a new access token.
-- For security, we only store a SHA-256 hash of the token in the database.
-- --

-- name: CreateRefreshToken :one
-- Inserts a new refresh token record into the database. It returns the newly
-- created record.
INSERT INTO refresh_tokens (
    id,
    user_id,
    token_hash,
    expires_at
) VALUES (
    ?, ?, ?, ?
)
RETURNING *;

-- name: GetRefreshTokenByHash :one
-- Retrieves a single refresh token by its SHA-256 hash. This is the primary
-- method for looking up a token when a user tries to refresh their session.
SELECT * FROM refresh_tokens
WHERE token_hash = ? LIMIT 1;

-- name: DeleteRefreshTokenByID :exec
-- Deletes a refresh token by its unique primary key (id). This is the most
-- efficient way to delete a token after it has been successfully used for rotation.
DELETE FROM refresh_tokens
WHERE id = ?;

-- name: DeleteUserRefreshTokens :exec
-- Deletes all refresh tokens associated with a specific user ID. This is a crucial
-- security measure to invalidate all sessions for a user if a compromised token
-- is detected or if they request a "log out from all devices" action.
DELETE FROM refresh_tokens
WHERE user_id = ?;

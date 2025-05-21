-- name: CreateUser :one
-- Inserts a new user into the database.
-- Returns the newly created user's ID.
INSERT INTO users (
    email,
    password_hash,
    role,
    claims,
    oauth_provider,
    oauth_id
) VALUES (
    ?, ?, ?, ?, ?, ?
)
RETURNING
    id,
    email,
    password_hash,
    role,
    claims,
    oauth_provider,
    oauth_id,
    created_at,
    updated_at,
    is_active;

-- name: GetUserByEmail :one
-- Retrieves a user by their email address.
-- Used for login and checking existing registrations.
SELECT
    id,
    email,
    password_hash,
    role,
    claims,
    oauth_provider,
    oauth_id,
    created_at,
    updated_at,
    is_active
FROM
    users
WHERE
    email = ?;

-- name: GetUserByID :one
-- Retrieves a user by their unique ID.
-- Used for session validation and fetching user details.
SELECT
    id,
    email,
    password_hash,
    role,
    claims,
    oauth_provider,
    oauth_id,
    created_at,
    updated_at,
    is_active
FROM
    users
WHERE
    id = ?;

-- name: UpdateUserPassword :exec
-- Updates a user's password hash and updates the 'updated_at' timestamp.
UPDATE
    users
SET
    password_hash = ?,
    updated_at = STRFTIME('%s', 'NOW')
WHERE
    id = ?;

-- name: UpdateUserRole :exec
-- Updates a user's role and updates the 'updated_at' timestamp.
UPDATE
    users
SET
    role = ?,
    updated_at = STRFTIME('%s', 'NOW')
WHERE
    id = ?;

-- name: UpdateUserClaims :exec
-- Updates a user's JSON claims data and updates the 'updated_at' timestamp.
UPDATE
    users
SET
    claims = ?,
    updated_at = STRFTIME('%s', 'NOW')
WHERE
    id = ?;

-- name: UpdateUserIsActive :exec
-- Updates a user's active status (e.g., for deactivation) and updates the 'updated_at' timestamp.
UPDATE
    users
SET
    is_active = ?,
    updated_at = STRFTIME('%s', 'NOW')
WHERE
    id = ?;

-- name: DeleteUser :exec
-- Deletes a user from the database by their ID.
DELETE FROM
    users
WHERE
    id = ?;

-- name: CheckEmailExists :one
-- Checks if an email address already exists in the database.
-- Returns a count (0 or 1).
SELECT
    COUNT(id)
FROM
    users
WHERE
    email = ?;

-- name: GetUserByOAuth :one
-- Retrieves a user by their OAuth provider and OAuth ID.
-- Used for logging in users who registered via an OAuth provider.
SELECT
    id,
    email,
    password_hash,
    role,
    claims,
    oauth_provider,
    oauth_id,
    created_at,
    updated_at,
    is_active
FROM
    users
WHERE
    oauth_provider = ? AND oauth_id = ?;

-- name: ListAllUsers :many
-- Retrieves all users from the database.
-- Useful for administrative purposes (e.g., user management panel).
SELECT
    id,
    email,
    password_hash,
    role,
    claims,
    oauth_provider,
    oauth_id,
    created_at,
    updated_at,
    is_active
FROM
    users
ORDER BY
    created_at DESC;

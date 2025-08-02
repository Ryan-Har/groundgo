-- This table stores active refresh tokens.
CREATE TABLE refresh_tokens (
    -- A unique identifier for the token record.
    id TEXT PRIMARY KEY,
    -- The user to whom the token belongs.
    user_id TEXT NOT NULL,
    -- A SHA-256 hash of the refresh token. This prevents a database breach
    -- from exposing the actual tokens. The refresh token itself is only known
    -- by the client and briefly by the application when issued/used.
    token_hash TEXT NOT NULL UNIQUE,
    -- Unix timestamp indicating when the refresh token expires.
    expires_at INTEGER NOT NULL,
    -- Unix timestamp when the token was issued.
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
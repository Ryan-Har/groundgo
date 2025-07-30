-- This table stores stateful session tokens.
-- Each row represents an active user session.
CREATE TABLE sessions (
    -- The cryptographically secure session token (32 bytes of entropy, hex-encoded to 64 chars).
    id TEXT PRIMARY KEY NOT NULL,
    -- Foreign key to the 'users' table.
    user_id TEXT NOT NULL,
    -- Unix timestamp indicating when the session will expire.
    expires_at INTEGER NOT NULL,
    -- The client's IP address at the time of session creation. Useful for security auditing.
    ip_address TEXT,
    -- The client's User-Agent string. Useful for security auditing.
    user_agent TEXT,
    -- Timestamp of when the session was created.
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    -- Ensures that if a user is deleted, all their sessions are automatically removed.
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Index to quickly look up all sessions belonging to a specific user.
-- This is useful for features like "log out on all other devices".
CREATE INDEX idx_sessions_user_id ON sessions(user_id);

-- Index to efficiently find and delete expired sessions.
-- A periodic cleanup job will use this index to purge old records.
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);

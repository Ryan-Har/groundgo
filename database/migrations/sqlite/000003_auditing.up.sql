-- This table stores bearer tokens (e.g., JWTs) that have been explicitly revoked.
-- Before accepting a bearer token, you should check if it exists in this table.
CREATE TABLE revoked_tokens (
    -- The unique identifier of the token. For a JWT, this should be the 'jti' claim.
    -- Using the full token signature is also an option but is less efficient.
    id TEXT PRIMARY KEY NOT NULL,
    -- The user to whom the token was issued.
    user_id TEXT NOT NULL,
    -- Unix timestamp indicating when the token was revoked.
    revoked_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    -- The original expiry time of the token. This allows a cleanup job
    -- to purge tokens from this table after they would have naturally expired anyway.
    original_expires_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Index to efficiently purge expired revoked tokens.
CREATE INDEX idx_revoked_tokens_expires_at ON revoked_tokens(original_expires_at);


-- This table provides a comprehensive audit trail for all security-sensitive events.
-- It creates an immutable log of actions for incident response and analysis.
CREATE TABLE auth_audit_log (
    -- A unique identifier for the log entry.
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- The user associated with the event. Can be NULL for system-level events
    -- or failed actions where a user could not be identified (e.g., bad username).
    user_id TEXT,
    -- A clear, machine-readable name for the event.
    -- Examples: 'USER_LOGIN_SUCCESS', 'USER_LOGIN_FAILURE', 'PASSWORD_RESET_REQUEST',
    -- 'SESSION_CREATED', 'TOKEN_REVOKED', 'USER_PERMISSIONS_CHANGED'.
    event_type TEXT NOT NULL,
    -- The IP address from which the event originated.
    ip_address TEXT,
    -- The User-Agent of the client that initiated the event.
    user_agent TEXT,
    -- A flexible field to store event-specific metadata as a JSON string.
    -- For a 'USER_LOGIN_FAILURE', this could contain {'reason': 'invalid_password'}.
    -- For 'USER_PERMISSIONS_CHANGED', it could contain {'added': ['admin'], 'removed': []}.
    details TEXT,
    -- Timestamp of when the event occurred.
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Index to quickly find all events for a specific user.
CREATE INDEX idx_auth_audit_log_user_id ON auth_audit_log(user_id);
-- Index to quickly find all events of a specific type.
CREATE INDEX idx_auth_audit_log_event_type ON auth_audit_log(event_type);
-- Index on the timestamp for time-based queries.
CREATE INDEX idx_auth_audit_log_created_at ON auth_audit_log(created_at);
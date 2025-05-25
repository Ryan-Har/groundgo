CREATE TABLE users (
    id TEXT PRIMARY KEY UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT,
    role TEXT NOT NULL DEFAULT 'user',
    claims TEXT, -- JSON data stored as TEXT
    oauth_provider TEXT,
    oauth_id TEXT,
    created_at INTEGER NOT NULL DEFAULT (STRFTIME('%s', 'NOW')), -- Unix timestamp (seconds since epoch)
    updated_at INTEGER NOT NULL DEFAULT (STRFTIME('%s', 'NOW')), -- Unix timestamp (seconds since epoch)
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);

-- Add an index to the email column for faster lookups
CREATE INDEX idx_users_id ON users (id);
CREATE INDEX idx_users_email ON users (email);

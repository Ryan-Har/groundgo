-- Drop the indexes first to remove dependencies.
DROP INDEX IF EXISTS idx_sessions_expires_at;
DROP INDEX IF EXISTS idx_sessions_user_id;

-- Drop the sessions table to fully revert the migration.
DROP TABLE IF EXISTS sessions;

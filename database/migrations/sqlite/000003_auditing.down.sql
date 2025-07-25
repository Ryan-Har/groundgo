-- Drop the audit log table and its indexes.
DROP INDEX IF EXISTS idx_auth_audit_log_created_at;
DROP INDEX IF EXISTS idx_auth_audit_log_event_type;
DROP INDEX IF EXISTS idx_auth_audit_log_user_id;
DROP TABLE IF EXISTS auth_audit_log;

-- Drop the revoked tokens table and its index.
DROP INDEX IF EXISTS idx_revoked_tokens_expires_at;
DROP TABLE IF EXISTS revoked_tokens;

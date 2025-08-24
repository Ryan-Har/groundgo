-- name: CreateAuditLog :one
-- CreateAuditLog inserts a new security event into the audit trail.
INSERT INTO auth_audit_log (
  user_id,
  event_type,
  ip_address,
  user_agent,
  details
) VALUES (
  ?, ?, ?, ?, ?
)
RETURNING *;

-- name: ListAuditLogsForUser :many
-- ListAuditLogsForUser retrieves a paginated list of audit events for a specific user,
-- ordered from newest to oldest.
SELECT * FROM auth_audit_log
WHERE user_id = ?
ORDER BY created_at DESC
LIMIT ? OFFSET ?;

-- name: ListAuditLogsByEventType :many
-- ListAuditLogsByEventType retrieves a paginated list of audit events of a specific type,
-- ordered from newest to oldest.
SELECT * FROM auth_audit_log
WHERE event_type = ?
ORDER BY created_at DESC
LIMIT ? OFFSET ?;
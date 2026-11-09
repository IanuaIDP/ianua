-- The provider session behind a session of a tenant.
SELECT session_id, connection_id, subject, session_index
FROM provider_sessions
WHERE tenant_id = $1 AND session_id = $2

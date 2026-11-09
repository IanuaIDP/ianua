-- Forgets the provider session behind a session of a tenant.
DELETE FROM provider_sessions
WHERE tenant_id = $1 AND session_id = $2

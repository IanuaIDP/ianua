-- Keeps the provider session behind a session of a tenant. One kept
-- already for the session is replaced.
INSERT INTO provider_sessions (tenant_id, session_id, connection_id, subject, session_index)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (tenant_id, session_id) DO UPDATE SET
    connection_id = EXCLUDED.connection_id,
    subject = EXCLUDED.subject,
    session_index = EXCLUDED.session_index

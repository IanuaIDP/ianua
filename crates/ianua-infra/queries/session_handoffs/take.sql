-- Removes and returns the pass of a tenant whose code hashes to the given
-- value, so a code is used once however many times it is sent.
DELETE FROM session_handoffs
WHERE tenant_id = $1 AND token_hash = $2
RETURNING token_hash, browser_hash, session_id, service_id, host, expires_at, consumed_at

-- Removes and returns the sign-in code of a tenant hashing to the given
-- value, so a code is used once however many times it is sent.
DELETE FROM sign_in_codes
WHERE tenant_id = $1 AND token_hash = $2
RETURNING token_hash, dashboard_hash, session_id, expires_at, consumed_at

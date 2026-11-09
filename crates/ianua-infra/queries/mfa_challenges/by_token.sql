-- The second-factor challenge of a tenant whose token hashes to the given
-- value.
SELECT token_hash, session_id, expires_at, failed_attempts, consumed_at
FROM mfa_challenges
WHERE tenant_id = $1 AND token_hash = $2

-- Removes the second-factor challenge of a tenant whose token hashes to
-- the given value.
DELETE FROM mfa_challenges
WHERE tenant_id = $1 AND token_hash = $2

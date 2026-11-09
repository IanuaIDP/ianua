-- The tenant API key, not expired and not paused, kept as a digest, with
-- its tenant, for a bearer whose tenant is not known yet. Two answers mean
-- a broken digest and are refused by the caller.
SELECT id, tenant_id
FROM api_keys
WHERE key_hash = $1 AND (expires_at IS NULL OR expires_at > $2) AND paused_at IS NULL
LIMIT 2

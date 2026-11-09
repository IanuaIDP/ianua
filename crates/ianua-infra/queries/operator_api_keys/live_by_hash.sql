-- The operator key, neither revoked nor expired, kept as a digest, with
-- its prefix, operator and end.
SELECT key_prefix, operator_id, expires_at
FROM operator_api_keys
WHERE key_hash = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > $2)

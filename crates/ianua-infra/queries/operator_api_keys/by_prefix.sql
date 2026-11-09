-- The operator API key shown with the given prefix.
SELECT key_prefix, operator_id, key_hash, expires_at, revoked_at, created_at
FROM operator_api_keys
WHERE key_prefix = $1

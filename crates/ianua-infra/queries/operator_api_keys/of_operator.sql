-- Every API key of one operator, revoked or not, oldest first.
SELECT key_prefix, operator_id, key_hash, expires_at, revoked_at, created_at
FROM operator_api_keys
WHERE operator_id = $1
ORDER BY created_at, key_prefix

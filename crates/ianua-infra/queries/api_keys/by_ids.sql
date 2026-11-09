-- The API keys of one tenant with the given ids.
SELECT id, name, key_prefix, key_hash, scopes, created_by, expires_at, last_used_at,
       last_used_ip, created_at, paused_at, seen_countries
FROM api_keys
WHERE tenant_id = $1 AND id = ANY($2)

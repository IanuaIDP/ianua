-- Keeps an API key one tenant just made.
INSERT INTO api_keys
    (id, tenant_id, name, key_prefix, key_hash, scopes, created_by, expires_at, last_used_at,
     last_used_ip, created_at, paused_at, seen_countries)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)

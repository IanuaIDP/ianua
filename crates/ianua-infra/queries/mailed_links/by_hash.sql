-- The link of one purpose a tenant mailed with the given hash.
SELECT token_hash, user_id, sent_to, created_at, expires_at, used_at
FROM mailed_links
WHERE tenant_id = $1 AND purpose = $2 AND token_hash = $3

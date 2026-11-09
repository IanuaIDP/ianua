-- The link of one purpose most recently mailed to a user of a tenant,
-- spent or not.
SELECT token_hash, user_id, sent_to, created_at, expires_at, used_at
FROM mailed_links
WHERE tenant_id = $1 AND user_id = $2 AND purpose = $3
ORDER BY created_at DESC
LIMIT 1

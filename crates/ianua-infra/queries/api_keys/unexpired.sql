-- How many of the tenant's API keys still work at the given moment. A
-- revoked key is deleted, so every key kept and not expired works.
SELECT count(*) AS "count!"
FROM api_keys
WHERE tenant_id = $1 AND (expires_at IS NULL OR expires_at > $2)

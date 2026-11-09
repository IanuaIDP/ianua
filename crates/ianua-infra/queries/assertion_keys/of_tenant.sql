-- Every assertion key of a tenant, oldest first, without its private half:
-- the side that rotates and publishes keys never reads one back.
SELECT kid, algorithm, public_key, status, rotated_at, created_at
FROM assertion_keys
WHERE tenant_id = $1
ORDER BY created_at, kid

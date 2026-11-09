-- The tenant's agents suspended now and last changed at or after the given
-- moment, oldest change first, at most the given number.
SELECT id
FROM agents
WHERE tenant_id = $1 AND status = 'suspended' AND updated_at >= $2
ORDER BY updated_at, id
LIMIT $3

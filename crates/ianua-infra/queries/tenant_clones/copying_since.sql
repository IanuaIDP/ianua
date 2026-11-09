-- The clones still copying that started before the cut-off, the oldest
-- first.
SELECT id, tenant_id
FROM tenant_clones
WHERE state = 'copying' AND started_at < $1
ORDER BY started_at, id
LIMIT $2

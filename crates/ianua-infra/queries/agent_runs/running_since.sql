-- The runs still running that started before the cut-off, of any tenant
-- of this database, the oldest first.
SELECT tenant_id, id, created_at
FROM agent_runs
WHERE status = 'running' AND created_at < $1
ORDER BY created_at, id
LIMIT $2

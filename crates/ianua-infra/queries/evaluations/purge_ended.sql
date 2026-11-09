-- Removes a tenant's evaluations that ended before the cutoff, a batch at a
-- time; evaluations still running are kept, however old.
DELETE FROM evaluations
WHERE id IN (
    SELECT id
    FROM evaluations
    WHERE tenant_id = $1 AND state <> 'running' AND updated_at < $2
    ORDER BY updated_at
    LIMIT $3
)

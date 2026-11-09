-- Removes a tenant's trials that ended before the cutoff, a batch at a
-- time; trials still running are kept, however old.
DELETE FROM sandbox_trials
WHERE id IN (
    SELECT id
    FROM sandbox_trials
    WHERE tenant_id = $1 AND state <> 'running' AND updated_at < $2
    ORDER BY updated_at
    LIMIT $3
)

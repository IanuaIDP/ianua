-- Gives a stored run of the tenant where its steps stand now, only while it
-- is still at the version the caller read, and answers the version it is
-- stored at now. Every write moves the version on, so a second write from
-- the same read finds no row. A run ends once: one that ended keeps how it
-- ended. No row comes back when the run changed since, ended otherwise, or
-- is gone.
UPDATE workflow_executions SET
    steps = $4,
    status = $5,
    cancelled_by = $6,
    deadline = $7,
    updated_at = GREATEST($8, updated_at + interval '1 microsecond')
WHERE tenant_id = $1 AND id = $2 AND updated_at = $3
    AND (status = 'running'
        OR (status = $5 AND cancelled_by IS NOT DISTINCT FROM $6))
RETURNING updated_at

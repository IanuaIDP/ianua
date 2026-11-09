-- Gives a stored teardown the steps done and the failure it has now, only
-- while it is still at the version the caller read, and answers the
-- version it is stored at now. Every write moves the version on, so of two
-- steps that finish at once and read the same version, the second finds no
-- row rather than writing its list of steps done over the first one's.
-- None comes back either when the teardown is gone. Its steps planned and
-- when it began never change.
UPDATE tenant_teardowns SET
    done = $3,
    failed_step = $4,
    failed_reason = $5,
    updated_at = GREATEST($6, updated_at + interval '1 microsecond')
WHERE tenant_id = $1 AND updated_at = $2
RETURNING updated_at

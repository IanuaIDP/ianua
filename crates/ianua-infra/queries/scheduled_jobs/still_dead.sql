-- Whether a job is still dead at the attempt an operator read, to tell a
-- retry left undone because the same work waits from one someone else
-- made first.
SELECT EXISTS (
    SELECT 1
    FROM scheduled_jobs
    WHERE id = $1 AND tenant_id IS NOT DISTINCT FROM $2
      AND status = 'dead' AND attempt = $3
) AS "dead!"

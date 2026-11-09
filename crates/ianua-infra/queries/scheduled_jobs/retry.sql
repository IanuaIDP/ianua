-- Puts a dead job back on the queue as an operator retried it: pending, due
-- at $5, with $4 attempts allowed. Only while it is still dead at the
-- attempt the operator read, so of two retries at once one changes it, and
-- only while no job with its key waits or runs. Matched on its tenant as
-- well as its id.
UPDATE scheduled_jobs AS j
SET status = $6, max_attempts = $4, run_at = $5
WHERE j.id = $1 AND j.tenant_id IS NOT DISTINCT FROM $2
  AND j.status = 'dead' AND j.attempt = $3
  AND NOT EXISTS (
      SELECT 1
      FROM scheduled_jobs AS live
      WHERE j.job_key IS NOT NULL
        AND live.job_key = j.job_key
        AND live.tenant_id IS NOT DISTINCT FROM j.tenant_id
        AND live.status IN ('pending', 'running')
  )
RETURNING id

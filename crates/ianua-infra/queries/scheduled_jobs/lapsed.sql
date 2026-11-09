-- The running jobs of a lane whose holder's lease ran out, locked for the
-- claim that gives them up.
SELECT id, tenant_id AS "tenant_id?", job_type, job_key, key_hold, payload, run_at, attempt, max_attempts,
       status, error, created_at, last_attempted_at
FROM scheduled_jobs
WHERE status = 'running' AND leased_until < $2 AND job_type = ANY($1)
ORDER BY leased_until, id
LIMIT $3
FOR UPDATE SKIP LOCKED

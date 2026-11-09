-- A tenant's job by its id.
SELECT id, tenant_id AS "tenant_id?", job_type, job_key, key_hold, payload, run_at, attempt, max_attempts,
       status, error, created_at, last_attempted_at
FROM scheduled_jobs
WHERE id = $1

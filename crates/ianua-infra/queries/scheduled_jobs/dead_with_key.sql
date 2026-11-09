-- The dead jobs of a tenant, or of no tenant, under a key, locked so the
-- job that did their work marks them superseded once.
SELECT id, tenant_id AS "tenant_id?", job_type, job_key, key_hold, payload, run_at, attempt,
       max_attempts, status, error, created_at, last_attempted_at
FROM scheduled_jobs
WHERE tenant_id IS NOT DISTINCT FROM $1 AND job_key = $2 AND status = 'dead'
FOR UPDATE

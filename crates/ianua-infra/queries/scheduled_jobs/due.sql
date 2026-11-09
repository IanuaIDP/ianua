-- The due pending jobs of a lane, oldest first, at most $4 of any one
-- tenant's and $5 in all. The oldest $3 are locked first, so two claims
-- never take the same job, then shared out between tenants.
WITH candidates AS (
    SELECT id, tenant_id, run_at
    FROM scheduled_jobs
    WHERE status = 'pending' AND job_type = ANY($1) AND run_at <= $2
    ORDER BY run_at, id
    LIMIT $3
    FOR UPDATE SKIP LOCKED
), ranked AS (
    SELECT id, run_at, row_number() OVER (PARTITION BY tenant_id ORDER BY run_at, id) AS place
    FROM candidates
)
SELECT j.id, j.tenant_id AS "tenant_id?", j.job_type, j.job_key, j.key_hold, j.payload, j.run_at, j.attempt,
       j.max_attempts, j.status, j.error, j.created_at, j.last_attempted_at
FROM ranked r
JOIN scheduled_jobs j ON j.id = r.id
WHERE r.place <= $4
ORDER BY r.run_at, r.id
LIMIT $5

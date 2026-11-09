-- Queues a tenant's job, unless a job with its key waits or runs already,
-- or, for work done once, a job with its key is kept at all.
INSERT INTO scheduled_jobs (
    id, tenant_id, job_type, job_key, key_hold, payload, run_at, attempt, max_attempts, status,
    error, created_at, last_attempted_at, leased_until
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NULL)
ON CONFLICT DO NOTHING
RETURNING id

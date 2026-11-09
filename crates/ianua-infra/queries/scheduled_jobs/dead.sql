-- The dead jobs queued before the cursor ($1, $2), newest first, at most
-- $3. A first page passes no cursor.
SELECT id, tenant_id AS "tenant_id?", job_type, job_key, key_hold, payload, run_at, attempt, max_attempts,
       status, error, created_at, last_attempted_at
FROM scheduled_jobs
WHERE status = 'dead'
  AND ($1::timestamptz IS NULL OR (created_at, id) < ($1, $2))
ORDER BY created_at DESC, id DESC
LIMIT $3

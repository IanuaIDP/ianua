-- One bounded round of ended jobs, skipping rows another cleanup holds.
-- Locked tuple locations remain valid within this statement and let the
-- delete revisit only the selected rows, without joining the whole backlog.
WITH expired AS (
    SELECT ctid, tenant_id
    FROM scheduled_jobs
    WHERE status IN ('completed', 'dead', 'superseded') AND created_at < $1
    LIMIT $2
    FOR UPDATE SKIP LOCKED
)
DELETE FROM scheduled_jobs AS jobs
USING expired
WHERE jobs.ctid = expired.ctid
  AND jobs.tenant_id IS NOT DISTINCT FROM expired.tenant_id

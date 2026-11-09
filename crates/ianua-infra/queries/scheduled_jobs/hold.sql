-- Marks the claimed jobs running at their attempts, held until $5. Each is
-- matched on its tenant as well as its id.
UPDATE scheduled_jobs AS j
SET status = 'running', attempt = held.attempt, last_attempted_at = held.attempted_at,
    leased_until = $5
FROM unnest($1::uuid[], $2::uuid[], $3::integer[], $4::timestamptz[])
    AS held (id, tenant_id, attempt, attempted_at)
WHERE j.id = held.id AND j.tenant_id IS NOT DISTINCT FROM held.tenant_id
  AND j.status = 'pending'

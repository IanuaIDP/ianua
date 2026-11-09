-- The tenants still provisioning, made before the cut-off, whose setup
-- never began, or stands running unchanged since the cut-off, the oldest
-- first. A setup that failed waits for an operator and is not one.
SELECT t.id
FROM tenants t
LEFT JOIN tenant_setups s ON s.tenant_id = t.id
WHERE t.status = 'provisioning' AND t.created_at < $1
  AND (s.tenant_id IS NULL
       OR (s.failed_step IS NULL AND NOT s.planned <@ s.done AND s.updated_at < $1))
ORDER BY t.created_at, t.id
LIMIT $2

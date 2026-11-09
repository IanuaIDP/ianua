-- The tenants deleted before the cut-off whose teardown never began, or
-- stands running unchanged since the cut-off, the oldest first. A
-- teardown that failed waits for an operator and is not one.
SELECT t.id
FROM tenants t
LEFT JOIN tenant_teardowns d ON d.tenant_id = t.id
WHERE t.status = 'deleted' AND t.updated_at < $1
  AND (d.tenant_id IS NULL
       OR (d.failed_step IS NULL AND NOT d.planned <@ d.done AND d.updated_at < $1))
ORDER BY t.updated_at, t.id
LIMIT $2

-- Every raised view of an operation's risk one tenant set, oldest first.
SELECT id, integration, operation, effect, raised_by, created_at, updated_at
FROM operation_risk_overrides
WHERE tenant_id = $1
ORDER BY created_at, id

-- One raised view of an operation's risk, of one tenant.
SELECT id, integration, operation, effect, raised_by, created_at, updated_at
FROM operation_risk_overrides
WHERE tenant_id = $1 AND id = $2

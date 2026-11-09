-- Deletes one raised view of an operation's risk, of one tenant.
DELETE FROM operation_risk_overrides
WHERE tenant_id = $1 AND id = $2

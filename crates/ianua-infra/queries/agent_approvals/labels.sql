-- The actions a tenant's approval requests with the given ids wait on, for the audit trail to name them by.
SELECT id, action AS name
FROM agent_approvals
WHERE tenant_id = $1 AND id = ANY($2)

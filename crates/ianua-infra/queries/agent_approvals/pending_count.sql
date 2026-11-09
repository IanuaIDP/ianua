-- How many requests of a tenant wait for a decision under one delegation,
-- while their time to decide has not run out.
SELECT count(*) AS "open!"
FROM agent_approvals
WHERE tenant_id = $1 AND delegation_id = $2 AND status = 'pending' AND $3 < expires_at

-- How many approval requests of a tenant wait for a decision against its
-- plan. One whose time to decide ran out waits for nobody, so it does not
-- count, though no sweep saved it as expired.
SELECT count(*) AS "count!"
FROM agent_approvals
WHERE tenant_id = $1 AND status = 'pending' AND $2 < expires_at

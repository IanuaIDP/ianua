-- How many agent runs a tenant has in flight against its plan: running,
-- waiting for an approval, or paused by a person, since a paused run goes
-- back to running with no check of its own.
SELECT count(*) AS "count!"
FROM agent_runs
WHERE tenant_id = $1 AND status IN ('running', 'awaiting_approval', 'paused')

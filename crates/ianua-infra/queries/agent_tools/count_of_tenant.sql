-- How many agent tools a tenant registered against its plan, disabled ones
-- too.
SELECT count(*) AS "count!"
FROM agent_tools
WHERE tenant_id = $1

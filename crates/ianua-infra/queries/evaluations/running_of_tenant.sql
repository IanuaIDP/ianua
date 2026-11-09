-- How many evaluations a tenant has running, held against its plan.
SELECT count(*) AS "count!"
FROM evaluations
WHERE tenant_id = $1 AND state = 'running'

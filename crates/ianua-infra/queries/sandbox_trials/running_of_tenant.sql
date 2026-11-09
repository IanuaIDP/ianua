-- How many trials a tenant has running, held against its plan.
SELECT count(*) AS "count!"
FROM sandbox_trials
WHERE tenant_id = $1 AND state = 'running'

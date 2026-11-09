-- How many model providers a tenant connected against its plan, disabled
-- ones too.
SELECT count(*) AS "count!"
FROM agent_model_providers
WHERE tenant_id = $1

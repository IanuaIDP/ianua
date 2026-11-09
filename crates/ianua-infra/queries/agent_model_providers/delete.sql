-- Removes a model provider of the tenant for good. The runs that reasoned
-- with it keep its id as history.
DELETE FROM agent_model_providers
WHERE tenant_id = $1 AND id = $2

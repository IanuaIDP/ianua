-- Removes an agent of the tenant for good; its keys, challenges,
-- delegations, requests and mark go with it by cascade.
DELETE FROM agents
WHERE tenant_id = $1 AND id = $2

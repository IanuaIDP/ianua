-- Removes a tool of the tenant for good.
DELETE FROM agent_tools
WHERE tenant_id = $1 AND id = $2

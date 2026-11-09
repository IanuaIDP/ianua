-- The tools of a tenant with the given ids.
SELECT id, name, description, input_schema, method, path, route_id, declared_action,
       action_class, data_class, status, created_at, updated_at
FROM agent_tools
WHERE tenant_id = $1 AND id = ANY($2)

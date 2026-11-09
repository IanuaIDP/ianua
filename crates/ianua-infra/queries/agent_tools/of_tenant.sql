-- Every tool of a tenant, oldest first.
SELECT id, name, description, input_schema, method, path, route_id, declared_action,
       action_class, data_class, status, created_at, updated_at
FROM agent_tools
WHERE tenant_id = $1
ORDER BY created_at, id

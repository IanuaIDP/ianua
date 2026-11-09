-- Keeps a tool: a new one is added, a known one of the same tenant takes
-- the new values. Its tenant and its creation time never change.
INSERT INTO agent_tools
    (id, tenant_id, name, description, input_schema, method, path, route_id,
     declared_action, action_class, data_class, status, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    input_schema = EXCLUDED.input_schema,
    method = EXCLUDED.method,
    path = EXCLUDED.path,
    route_id = EXCLUDED.route_id,
    declared_action = EXCLUDED.declared_action,
    action_class = EXCLUDED.action_class,
    data_class = EXCLUDED.data_class,
    status = EXCLUDED.status,
    updated_at = EXCLUDED.updated_at
WHERE agent_tools.tenant_id = EXCLUDED.tenant_id

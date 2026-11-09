-- Keeps a route: a new one is added, a known one of the same tenant takes
-- the new values. Its tenant and creation time never change.
INSERT INTO routes
    (id, tenant_id, name, path_pattern, methods, service_id, policy, hosts,
     conditions, pipeline_id, path_rewrite, status, priority, data_class,
     action_class, reach, parameter_rules, workflow_use, attack_mode_until,
     created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    path_pattern = EXCLUDED.path_pattern,
    methods = EXCLUDED.methods,
    service_id = EXCLUDED.service_id,
    policy = EXCLUDED.policy,
    hosts = EXCLUDED.hosts,
    conditions = EXCLUDED.conditions,
    pipeline_id = EXCLUDED.pipeline_id,
    path_rewrite = EXCLUDED.path_rewrite,
    status = EXCLUDED.status,
    priority = EXCLUDED.priority,
    data_class = EXCLUDED.data_class,
    action_class = EXCLUDED.action_class,
    reach = EXCLUDED.reach,
    parameter_rules = EXCLUDED.parameter_rules,
    workflow_use = EXCLUDED.workflow_use,
    attack_mode_until = EXCLUDED.attack_mode_until,
    updated_at = EXCLUDED.updated_at
WHERE routes.tenant_id = EXCLUDED.tenant_id

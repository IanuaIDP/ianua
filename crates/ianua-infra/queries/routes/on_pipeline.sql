-- Every route of one tenant that runs the given pipeline, whatever its
-- status, in priority order.
SELECT id, name, path_pattern, methods, service_id, policy, hosts, conditions,
       pipeline_id, path_rewrite, status, priority, data_class, action_class,
       reach, parameter_rules, workflow_use, attack_mode_until, created_at, updated_at
FROM routes
WHERE tenant_id = $1 AND pipeline_id = $2
ORDER BY priority, id

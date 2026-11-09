-- Every active route of one tenant open to its workflows, in priority
-- order: the apps a Protected apps step may call.
SELECT id, name, path_pattern, methods, service_id, policy, hosts, conditions,
       pipeline_id, path_rewrite, status, priority, data_class, action_class,
       reach, parameter_rules, workflow_use, attack_mode_until, created_at, updated_at
FROM routes
WHERE tenant_id = $1 AND status = 'active' AND workflow_use = 'open'
ORDER BY priority, id

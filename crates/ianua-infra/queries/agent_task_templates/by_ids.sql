-- The task templates of a tenant with the given ids.
SELECT id, name, purpose, purpose_digest, ceiling, action_classes, max_ttl_seconds, max_depth,
       max_data_class, resource_scope, budget, approval, proposed_by_kind, proposed_by_id,
       proposed_by_person, proposed_at, approved_by_kind, approved_by_id, approved_by_person,
       approved_at, retired_at
FROM agent_task_templates
WHERE tenant_id = $1 AND id = ANY($2)

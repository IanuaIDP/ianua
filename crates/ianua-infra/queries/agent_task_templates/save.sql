-- Keeps a task template: a new one is added, a known one of the same
-- tenant takes its approval and its withdrawal. What it allows, who
-- proposed it and when never change.
INSERT INTO agent_task_templates
    (id, tenant_id, name, purpose, purpose_digest, ceiling, action_classes, max_ttl_seconds,
     max_depth, max_data_class, resource_scope, budget, approval, proposed_by_kind,
     proposed_by_id, proposed_by_person, proposed_at, approved_by_kind, approved_by_id,
     approved_by_person, approved_at, retired_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19,
        $20, $21, $22)
ON CONFLICT (id) DO UPDATE SET
    approved_by_kind = EXCLUDED.approved_by_kind,
    approved_by_id = EXCLUDED.approved_by_id,
    approved_by_person = EXCLUDED.approved_by_person,
    approved_at = EXCLUDED.approved_at,
    retired_at = EXCLUDED.retired_at
WHERE agent_task_templates.tenant_id = EXCLUDED.tenant_id

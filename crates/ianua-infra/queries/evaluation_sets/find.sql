-- The sample cases of one workflow of a tenant.
SELECT workflow_id, cases, publish_gate, edited_by, created_at, updated_at
FROM evaluation_sets
WHERE tenant_id = $1 AND workflow_id = $2

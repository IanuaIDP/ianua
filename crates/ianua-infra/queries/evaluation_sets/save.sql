-- Keeps a workflow's sample cases: the first set is added, a later save
-- takes its cases, gate, editor and when it changed. When it was first
-- made never changes.
INSERT INTO evaluation_sets
    (tenant_id, workflow_id, cases, publish_gate, edited_by, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (tenant_id, workflow_id) DO UPDATE SET
    cases = EXCLUDED.cases,
    publish_gate = EXCLUDED.publish_gate,
    edited_by = EXCLUDED.edited_by,
    updated_at = EXCLUDED.updated_at

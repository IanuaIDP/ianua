-- Keeps a review assignment: a new one is added, a known one of the same
-- tenant takes its end. The two agents, who assigned it and when never
-- change.
INSERT INTO agent_review_assignments
    (id, tenant_id, reviewer_id, reviewed_id, assigned_by_kind, assigned_by_id, assigned_at,
     ended_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (id) DO UPDATE SET
    ended_at = EXCLUDED.ended_at
WHERE agent_review_assignments.tenant_id = EXCLUDED.tenant_id

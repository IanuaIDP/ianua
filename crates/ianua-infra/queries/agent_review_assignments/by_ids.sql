-- The review assignments of a tenant with the given ids.
SELECT id, reviewer_id, reviewed_id, assigned_by_kind, assigned_by_id, assigned_at, ended_at
FROM agent_review_assignments
WHERE tenant_id = $1 AND id = ANY($2)

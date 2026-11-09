-- The review assignments of a tenant one agent is part of, as reviewer or
-- reviewed, newest first, ended ones included.
SELECT id, reviewer_id, reviewed_id, assigned_by_kind, assigned_by_id, assigned_at, ended_at
FROM agent_review_assignments
WHERE tenant_id = $1 AND (reviewer_id = $2 OR reviewed_id = $2)
ORDER BY assigned_at DESC, id DESC

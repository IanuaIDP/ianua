-- How many approvals one person gave in a tenant since a time: the ones
-- that granted a request, and the first of two. A denial is not one.
SELECT (
    SELECT count(*)
    FROM agent_approvals
    WHERE tenant_id = $1 AND decided_by_kind = $2 AND decided_by_id = $3 AND decided_at >= $4
      AND status IN ('approved', 'consumed')
) + (
    SELECT count(*)
    FROM agent_approvals
    WHERE tenant_id = $1 AND first_by_kind = $2 AND first_by_id = $3 AND first_at >= $4
) AS "signed!"

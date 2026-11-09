-- Spends the oldest approved request of a tenant for exactly one action
-- under one delegation, while its time has not run out, in one statement,
-- and answers which one it spent. Two calls racing for it cannot both
-- spend it: the one that finds it locked passes it over, and the spend
-- holds only while it is still approved.
UPDATE agent_approvals SET
    status = 'consumed',
    updated_at = greatest($4, updated_at)
WHERE tenant_id = $1 AND status = 'approved' AND id = (
    SELECT id
    FROM agent_approvals
    WHERE tenant_id = $1 AND delegation_id = $2 AND status = 'approved' AND action = $3
      AND $4 < expires_at
    ORDER BY created_at, id
    LIMIT 1
    FOR UPDATE SKIP LOCKED
)
RETURNING id

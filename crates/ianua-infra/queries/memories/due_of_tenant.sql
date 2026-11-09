-- Whether one tenant holds a memory whose waiting period is over at $2.
SELECT EXISTS (
    SELECT 1 FROM memories
    WHERE tenant_id = $1 AND status = 'deletion_requested' AND deleted_after <= $2
) AS "due!"

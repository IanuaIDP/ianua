-- Whether one tenant, read from the database of its own it lives in, holds
-- an assertion key rotated out and not yet retired.
SELECT EXISTS (
    SELECT 1 FROM assertion_keys WHERE tenant_id = $1 AND status = 'rotated'
) AS "held!"

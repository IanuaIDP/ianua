-- Whether one tenant, read from the database of its own it lives in, holds
-- an active key made before the cutoff.
SELECT EXISTS (
    SELECT 1 FROM signing_keys
    WHERE tenant_id = $1 AND status = 'active' AND created_at < $2
) AS "held!"
